package main

import (
	"encoding/json"
	"fmt"
	config "haikyu"
	"haikyu/internal/ierrors"
	"haikyu/internal/mempool"
	"haikyu/internal/miner"
	"haikyu/internal/path"
	"io/fs"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

type ProgressBar struct {
	Total   int
	Current int
	rate    string
}

func (p *ProgressBar) Play(cur int) {
	percent := float64(cur) / float64(p.Total) * 100
	fmt.Printf("\r[%-50s]%3d%% %8d/%d", strings.Repeat("#", int(percent/2)), uint(percent), cur, p.Total)
}

func main() {

	f, err := os.Create("cpuprofile")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()
	defer pprof.StopCPUProfile()

	pprof.StartCPUProfile(f)

	os.Remove(path.DBPath)

	defer func() {
		if err := recover(); err != nil {
			logrus.Error(err)
		}
	}()

	logger := logrus.New()
	// logger.SetLevel(logrus.InfoLevel)
	logger.SetLevel(logrus.PanicLevel)
	logger.Formatter = &logrus.TextFormatter{
		DisableColors: false,
		ForceColors:   true,
	}

	mempoolConfig := mempool.Opts{
		MaxMemPoolSize: config.MaxMemPoolSize,
		Logger:         logger,

		Dust: uint64(config.Dust),
	}

	// init mempool
	pool, err := mempool.New(sqlite.Open(path.DBPath), mempoolConfig, &gorm.Config{
		NowFunc:                func() time.Time { return time.Now().UTC() },
		Logger:                 gormLogger.Default.LogMode(gormLogger.Silent),
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
	})
	if err != nil {
		panic(err)
	}

	logger.Info("mempool initialized")

	// loop through all files in ./data/mempool
	// unmarshal all json objects
	files, err := os.ReadDir(path.MempoolDataPath)
	if err != nil {
		panic(err)
	}

	totalFiles := len(files)
	logger.Info("loading ", totalFiles, " files")
	pb := &ProgressBar{
		Total:   totalFiles,
		Current: 0,
		rate:    "#",
	}

	wg := new(sync.WaitGroup)
	doneChan := make(chan struct{}, totalFiles)

	rejectedTxFile := "rejected.txt"
	if _, err := os.Stat(path.Root + "/" + rejectedTxFile); err == nil {
		os.Remove(path.Root + "/" + rejectedTxFile)
	}

	rejTxFile, err := os.OpenFile(path.Root+"/"+rejectedTxFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer rejTxFile.Close()

	acceptableErrs := []string{
		ierrors.ErrAsmAndScriptMismatch.Error(),
		ierrors.ErrFeeTooLow.Error(),
	}

	start := time.Now()

	// Create a channel to distribute files to workers
	fileChan := make(chan fs.DirEntry, totalFiles)

	// Determine the number of worker goroutines (e.g., number of CPU cores)
	numWorkers := runtime.NumCPU()

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(&pool, fileChan, doneChan, wg, logger, rejTxFile, acceptableErrs)
	}

	// Send files to the channel
	for _, file := range files {
		if file.IsDir() && strings.Split(file.Name(), ".")[1] != "json" {
			logger.Info("skipping ", file.Name())
			continue
		}
		fileChan <- file
	}
	close(fileChan)

	// Track progress
	for i := 0; i < totalFiles; i++ {
		<-doneChan
		pb.Current++
		if pb.Current%1000 == 0 {
			pb.Play(pb.Current)
		}
	}

	fmt.Println("")

	wg.Wait()
	elapsed := time.Since(start)
	logger.Info("loaded ", totalFiles, " transactions into Mempool", " in ", elapsed.Seconds(), " seconds")

	logger.Info("starting miner")

	miner, err := miner.New(pool, miner.Opts{
		Logger:       logger,
		MaxBlockSize: uint(config.MAX_BLOCK_SIZE),
	})

	if err != nil {
		panic(err)
	}

	if err := miner.Mine(); err != nil {
		panic(err)
	}

}

// worker function to process files
func worker(pool *mempool.Mempool, fileChan <-chan fs.DirEntry, doneChan chan<- struct{}, wg *sync.WaitGroup, logger *logrus.Logger, rejTxFile *os.File, acceptableErrs []string) {
	defer wg.Done()

	for file := range fileChan {
		txData, err := os.ReadFile(path.MempoolDataPath + "/" + file.Name())
		if err != nil {
			panic(err)
		}

		var tx mempool.Transaction
		if err := json.Unmarshal(txData, &tx); err != nil {
			panic(err)
		}

		if err := (*pool).PutTx(tx); err != nil {
			logger.Info("processing ", file.Name())
			rejTxFile.WriteString(file.Name() + " Reason: " + err.Error() + "\n")

			if Contains(err.Error(), acceptableErrs) {
				doneChan <- struct{}{}
				continue
			}
			panic(err)
		}
		doneChan <- struct{}{}
	}
}

func Contains(target string, array []string) bool {
	for _, element := range array {
		if element == target {
			return true
		}
	}
	return false
}
