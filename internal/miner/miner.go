package miner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	config "haikyu"
	"haikyu/internal/ierrors"
	"haikyu/internal/mempool"
	"haikyu/internal/path"
	"haikyu/pkg/block"
	"haikyu/pkg/transaction"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

const (
	logFilePath        = "../miner.log"
	logFilePermissions = 0666
	initialWTXID       = "0000000000000000000000000000000000000000000000000000000000000000"
	givenDifficultyHex = "0000ffff00000000000000000000000000000000000000000000000000000000"
	coinbaseTxid       = "0000000000000000000000000000000000000000000000000000000000000000"
	coinbaseVout       = 0xffffffff
	coinbaseScriptSig  = "0368c10c"
	coinbaseSequence   = 0xffffffff
	coinbaseWitness    = "0000000000000000000000000000000000000000000000000000000000000000"
	miningRoutines     = 10
	blockVersion       = 4
	nBits              = 0x1f00ffff
	previousBlockHash  = "0000000000000000000000000000000000000000000000000000000000000000"
)

// miner represents the mining process and holds necessary data structures.
type miner struct {
	block   *block.Block    // The block being mined
	mempool mempool.Mempool // Reference to the mempool for transaction selection
	logger  *logrus.Logger  // Logger for miner-specific logging

	maxBlockSize uint // Maximum allowed block size in weight units
}

// New creates and returns a new miner instance with the given mempool and options.
func New(mempool mempool.Mempool, opts Opts) (*miner, error) {
	logger := logrus.New()
	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logFilePermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	logger.SetOutput(io.MultiWriter(os.Stdout, file))

	return &miner{
		block:        &block.Block{},
		logger:       logger,
		maxBlockSize: opts.MaxBlockSize,
		mempool:      mempool,
	}, nil
}

// Mine performs the block building and mining process.
func (m *miner) Mine() error {
	weight := 0
	feeCollected := 0
	wTxids := []string{initialWTXID}

	givenDifficulty, err := HexDecode(givenDifficultyHex)
	if err != nil {
		return fmt.Errorf("failed to decode given difficulty: %w", err)
	}

	if err := m.buildBlock(&weight, &feeCollected, &wTxids); err != nil {
		return fmt.Errorf("failed to build block: %w", err)
	}

	if err := m.createCoinbaseTransaction(feeCollected, wTxids); err != nil {
		return fmt.Errorf("failed to create coinbase transaction: %w", err)
	}

	if err := m.mineBlock(givenDifficulty); err != nil {
		return fmt.Errorf("failed to mine block: %w", err)
	}

	if err := m.writeOutputFile(); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	m.logMiningResults(feeCollected, weight)

	return nil
}

func (m *miner) buildBlock(weight, feeCollected *int, wTxids *[]string) error {
PICK_TX:
	for *weight < config.MAX_BLOCK_SIZE {
		tx, err := m.pickTransaction(*weight)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				m.logger.Info("No more suitable transactions found")
				break PICK_TX
			}
			return err
		}

		m.logTransactionProcessing(tx, *feeCollected, *weight)

		inputs, err := m.mempool.GetInputs(tx.Hash)
		if err != nil {
			m.logger.WithError(err).Error("Unable to get inputs")
			continue PICK_TX
		}

		if err := m.validateAndProcessTransaction(tx, inputs); err != nil {
			continue PICK_TX
		}

		*weight, *feeCollected = m.updateBlockStats(tx, *weight, *feeCollected)
		m.updateBlockTransactions(tx, wTxids)
	}
	return nil
}

func (m *miner) pickTransaction(currentWeight int) (transaction.Tx, error) {
	tx, err := m.mempool.PickBestTx()
	if err != nil {
		return transaction.Tx{}, err
	}

	if currentWeight+int(tx.Weight) > config.MAX_BLOCK_SIZE {
		return m.mempool.PickBestTxWithinWeight(uint64(config.MAX_BLOCK_SIZE - currentWeight))
	}

	return tx, nil
}

func (m *miner) validateAndProcessTransaction(tx transaction.Tx, inputs []transaction.InputTx) error {
	if err := m.mempool.ValidateWholeTx(tx, inputs); err != nil {
		m.logger.WithFields(logrus.Fields{
			"txHash": tx.Hash,
			"reason": "Invalid tx",
		}).Info("Rejected transaction")
		return err
	}

	for _, input := range inputs {
		if err := m.mempool.MarkOutPointSpent(input.FundingTxHash, input.FundingIndex); err != nil {
			if errors.Is(err, ierrors.ErrAlreadySpent) {
				m.logger.WithFields(logrus.Fields{
					"txHash": tx.Hash,
					"reason": "Already spent",
				}).Info("Rejected transaction")
				return err
			}
		}
	}

	if err := m.mempool.DeleteTx(tx.ID); err != nil {
		m.logger.WithError(err).Error("Unable to delete tx")
		return err
	}

	return nil
}

func (m *miner) updateBlockStats(tx transaction.Tx, weight, feeCollected int) (int, int) {
	weight += int(tx.Weight)
	feeCollected += int(tx.FeeCollected)
	return weight, feeCollected
}

func (m *miner) updateBlockTransactions(tx transaction.Tx, wTxids *[]string) {
	m.block.Txs = append(m.block.Txs, tx.Hash) // hash is in LittleEndian
	*wTxids = append(*wTxids, tx.WTXID)        // wTxid is in LittleEndian
}

func (m *miner) createCoinbaseTransaction(feeCollected int, wTxids []string) error {
	coinbaseVin := mempool.TxIn{
		Txid:       coinbaseTxid,
		Vout:       coinbaseVout,
		ScriptSig:  coinbaseScriptSig,
		Sequence:   coinbaseSequence,
		Witness:    []string{coinbaseWitness},
		IsCoinbase: true,
	}

	merkleRoot, err := GenerateMerkleRoot(wTxids)
	if err != nil {
		return fmt.Errorf("failed to generate merkle root: %w", err)
	}

	coinbaseVouts := []mempool.TxOut{
		{
			Value:        0,
			ScriptPubKey: "6a24aa21a9ed" + Hash256(merkleRoot+initialWTXID),
		},
		{
			Value:        uint64(feeCollected),
			ScriptPubKey: "76a914536ffa992491508dca0354e52f32a3a7a679a53a88ac",
		},
	}

	coinbaseTx := mempool.Transaction{
		Version:  2,
		Locktime: 0,
		Vin:      []mempool.TxIn{coinbaseVin},
		Vout:     coinbaseVouts,
	}

	cbTxId, _, _, err := coinbaseTx.Hash()
	if err != nil {
		return fmt.Errorf("failed to hash coinbase transaction: %w", err)
	}

	m.block.Txs = append([]string{cbTxId}, m.block.Txs...)
	return nil
}

func (m *miner) mineBlock(givenDifficulty []byte) error {
	blockHeader, err := m.createBlockHeader()
	if err != nil {
		return fmt.Errorf("failed to create block header: %w", err)
	}

	nonce, err := m.findNonce(blockHeader, givenDifficulty)
	if err != nil {
		return fmt.Errorf("failed to find nonce: %w", err)
	}

	blockHeader.Nonce = nonce
	m.block.Header = blockHeader

	blockHash := doubleHash(blockHeader.Serialize())
	m.logger.WithFields(logrus.Fields{
		"nonce": nonce,
		"hash":  hex.EncodeToString(blockHash),
	}).Info("Block mined")

	return nil
}

func (m *miner) createBlockHeader() (block.BlocKHeader, error) {
	merkleRoot, err := GenerateMerkleRoot(m.block.Txs)
	if err != nil {
		return block.BlocKHeader{}, fmt.Errorf("failed to generate merkle root: %w", err)
	}

	return block.BlocKHeader{
		Version:           blockVersion,
		TimeStamp:         uint32(time.Now().Unix()),
		NBits:             nBits,
		PreviousBlockHash: previousBlockHash,
		Nonce:             0,
		MerkleRoot:        reverseStringByteOrder(merkleRoot),
	}, nil
}

func (m *miner) findNonce(blockHeader block.BlocKHeader, givenDifficulty []byte) (uint32, error) {
	respChan := make(chan uint32, miningRoutines)
	errChan := make(chan error, miningRoutines)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	nextNonce := uint32(0)

	for i := 0; i < miningRoutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.mineRoutine(ctx, blockHeader, givenDifficulty, &nextNonce, respChan, errChan)
		}()
	}

	go func() {
		wg.Wait()
		close(respChan)
		close(errChan)
	}()

	select {
	case nonce := <-respChan:
		return nonce, nil
	case err := <-errChan:
		return 0, err
	}
}

func (m *miner) mineRoutine(ctx context.Context, blockHeader block.BlocKHeader, givenDifficulty []byte, nextNonce *uint32, respChan chan<- uint32, errChan chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			blockHeader.Nonce = atomic.AddUint32(nextNonce, 1)
			blockHash := doubleHash(blockHeader.Serialize())
			if bytes.Compare(reverseByteOrder(blockHash), givenDifficulty) < 0 {
				respChan <- blockHeader.Nonce
				return
			}
		}
	}
}

func (m *miner) writeOutputFile() error {
	os.Remove(path.OutFilePath)

	file, err := os.OpenFile(path.OutFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	file.WriteString(hex.EncodeToString(m.block.Header.Serialize()) + "\n")

	// Replace the GetTxByHash call with a method to reconstruct the coinbase transaction
	coinbaseTx, err := m.reconstructCoinbaseTransaction()
	if err != nil {
		return fmt.Errorf("failed to reconstruct coinbase transaction: %w", err)
	}

	_, cb_w_ser, _, err := coinbaseTx.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize coinbase transaction: %w", err)
	}

	file.WriteString(hex.EncodeToString(cb_w_ser) + "\n")
	for _, txId := range m.block.Txs {
		file.WriteString(reverseStringByteOrder(txId) + "\n")
	}

	return nil
}

// doubleHash performs a double SHA256 hash on the input data.
func doubleHash(header []byte) []byte {
	h := sha256.New()
	h.Write(header)
	firstHash := h.Sum(nil)

	h.Reset()
	h.Write(firstHash)

	return h.Sum(nil)
}

// reverseByteOrder reverses the order of bytes in a byte slice.
func reverseByteOrder(input []byte) []byte {
	for i, j := 0, len(input)-1; i < j; i, j = i+1, j-1 {
		input[i], input[j] = input[j], input[i]
	}
	return input
}

// reverseStringByteOrder reverses the byte order of a hexadecimal string.
func reverseStringByteOrder(hash string) string {
	reverse, _ := hex.DecodeString(hash)
	for i, j := 0, len(reverse)-1; i < j; i, j = i+1, j-1 {
		reverse[i], reverse[j] = reverse[j], reverse[i]
	}
	return hex.EncodeToString(reverse)
}

func (m *miner) logTransactionProcessing(tx transaction.Tx, feeCollected, weight int) {
	m.logger.WithFields(logrus.Fields{
		"tx":           tx.Hash,
		"feeCollected": feeCollected,
		"weight":       weight,
	}).Info("Processing transaction")
}

func (m *miner) logMiningResults(feeCollected, weight int) {
	m.logger.WithFields(logrus.Fields{
		"nonce":        m.block.Header.Nonce,
		"feeCollected": feeCollected,
		"weight":       weight,
	}).Info("Mined block")
}

func (m *miner) reconstructCoinbaseTransaction() (mempool.Transaction, error) {
	if len(m.block.Txs) == 0 {
		return mempool.Transaction{}, errors.New("no transactions in block")
	}

	feeCollected := m.calculateFeeCollected()

	merkleRoot, err := GenerateMerkleRoot(m.block.Txs)
	if err != nil {
		return mempool.Transaction{}, fmt.Errorf("failed to generate merkle root: %w", err)
	}

	return mempool.Transaction{
		Version:  2,
		Locktime: 0,
		Vin: []mempool.TxIn{{
			Txid:       coinbaseTxid,
			Vout:       coinbaseVout,
			ScriptSig:  coinbaseScriptSig,
			Sequence:   coinbaseSequence,
			Witness:    []string{coinbaseWitness},
			IsCoinbase: true,
		}},
		Vout: []mempool.TxOut{
			{
				Value:        0,
				ScriptPubKey: "6a24aa21a9ed" + Hash256(merkleRoot+initialWTXID),
			},
			{
				Value:        uint64(feeCollected),
				ScriptPubKey: "76a914536ffa992491508dca0354e52f32a3a7a679a53a88ac",
			},
		},
	}, nil
}

func (m *miner) calculateFeeCollected() int {
	feeCollected := 0
	for _, tx := range m.block.Txs[1:] { // Skip coinbase transaction
		// Assuming you have a way to get the fee for each transaction
		// This is a placeholder and should be replaced with actual fee calculation
		feeCollected += getFeeForTransaction(tx)
	}
	return feeCollected
}

// getFeeForTransaction is a placeholder function and should be implemented
// to return the actual fee for a given transaction
func getFeeForTransaction(txID string) int {
	// Implementation needed
	return 0
}
