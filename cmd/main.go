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

const (
	cpuProfileFile   = "cpuprofile"
	rejectedTxFile   = "rejected_transactions.txt"
	progressBarWidth = 50
	updateInterval   = 1000
)

// ProgressBar represents a progress bar for displaying task completion.
type ProgressBar struct {
	Total   int    // Total number of tasks
	Current int    // Current number of completed tasks
	rate    string // Visual representation of progress
}

// Play updates and displays the progress bar.
func (p *ProgressBar) Play(cur int) {
	percent := float64(cur) / float64(p.Total) * 100
	fmt.Printf("\r[%-*s]%3d%% %8d/%d", progressBarWidth, strings.Repeat("#", int(percent/2)), uint(percent), cur, p.Total)
}

func main() {
	setupProfiling()
	defer pprof.StopCPUProfile()

	os.Remove(path.DBPath)

	defer func() {
		if err := recover(); err != nil {
			logrus.Error(err)
		}
	}()

	logger := setupLogger()
	pool := initializeMempool(logger)
	processTransactionFiles(pool, logger)
	startMiner(pool, logger)
}

// setupProfiling initializes CPU profiling for performance analysis.
func setupProfiling() {
	f, err := os.Create(cpuProfileFile)
	if err != nil {
		fmt.Println("Error creating CPU profile:", err)
		return
	}
	pprof.StartCPUProfile(f)
}

// setupLogger configures and returns a logrus logger for application-wide logging.
func setupLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	logger.Formatter = &logrus.TextFormatter{
		DisableColors: false,
		ForceColors:   true,
	}
	return logger
}

// initializeMempool sets up and returns a new mempool instance with the specified configuration.
func initializeMempool(logger *logrus.Logger) mempool.Mempool {
	mempoolConfig := mempool.Opts{
		MaxMemPoolSize: config.MaxMemPoolSize,
		Logger:         logger,
		Dust:           uint64(config.Dust),
	}

	pool, err := mempool.New(sqlite.Open(path.DBPath), mempoolConfig, &gorm.Config{
		NowFunc:                func() time.Time { return time.Now().UTC() },
		Logger:                 gormLogger.Default.LogMode(gormLogger.Silent),
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
	})
	if err != nil {
		panic(err)
	}

	logger.Info("Mempool initialized")
	return pool
}

// processTransactionFiles reads and processes transaction files concurrently.
// It uses a worker pool to handle file processing and updates a progress bar.
func processTransactionFiles(pool mempool.Mempool, logger *logrus.Logger) {
	files, err := os.ReadDir(path.MempoolDataPath)
	if err != nil {
		panic(err)
	}

	totalFiles := len(files)
	logger.Info("Loading ", totalFiles, " files")

	pb := &ProgressBar{
		Total:   totalFiles,
		Current: 0,
		rate:    "#",
	}

	wg := new(sync.WaitGroup)
	doneChan := make(chan struct{}, totalFiles)
	fileChan := make(chan fs.DirEntry, totalFiles)

	rejTxFile := setupRejectedTxFile()
	defer rejTxFile.Close()

	acceptableErrs := []string{
		ierrors.ErrAsmAndScriptMismatch.Error(),
		ierrors.ErrFeeTooLow.Error(),
	}

	start := time.Now()

	numWorkers := runtime.NumCPU()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(pool, fileChan, doneChan, wg, logger, rejTxFile, acceptableErrs)
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			fileChan <- file
		}
	}
	close(fileChan)

	for i := 0; i < totalFiles; i++ {
		<-doneChan
		pb.Current++
		if pb.Current%updateInterval == 0 {
			pb.Play(pb.Current)
		}
	}

	fmt.Println("")
	wg.Wait()
	elapsed := time.Since(start)
	logger.Info("Loaded ", totalFiles, " transactions into Mempool in ", elapsed.Seconds(), " seconds")
}

// setupRejectedTxFile creates and returns a file for storing rejected transaction information.
func setupRejectedTxFile() *os.File {
	rejectedFilePath := path.Root + "/" + rejectedTxFile
	if _, err := os.Stat(rejectedFilePath); err == nil {
		os.Remove(rejectedFilePath)
	}

	rejTxFile, err := os.OpenFile(rejectedFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	return rejTxFile
}

// startMiner initializes and starts the mining process using the populated mempool.
func startMiner(pool mempool.Mempool, logger *logrus.Logger) {
	logger.Info("Starting miner")

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

// worker is a goroutine that processes transaction files concurrently.
// It reads JSON files, unmarshals transactions, and adds them to the mempool.
func worker(pool mempool.Mempool, fileChan <-chan fs.DirEntry, doneChan chan<- struct{}, wg *sync.WaitGroup, logger *logrus.Logger, rejTxFile *os.File, acceptableErrs []string) {
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

		if err := pool.PutTx(tx); err != nil {
			logger.Info("Processing ", file.Name())
			rejTxFile.WriteString(file.Name() + " Reason: " + err.Error() + "\n")

			if contains(err.Error(), acceptableErrs) {
				doneChan <- struct{}{}
				continue
			}
			panic(err)
		}
		doneChan <- struct{}{}
	}
}

// contains checks if a target string is present in a slice of strings.
func contains(target string, array []string) bool {
	for _, element := range array {
		if element == target {
			return true
		}
	}
	return false
}
