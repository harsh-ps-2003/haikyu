package miner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	config "haikyu"
	"haikyu/internal/ierrors"
	"haikyu/internal/mempool"
	"haikyu/internal/path"
	"haikyu/pkg/block"
	"os"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// miner represents the mining process and holds necessary data structures.
type miner struct {
	block   *block.Block    // The block being mined
	mempool mempool.Mempool // Reference to the mempool for transaction selection

	logger         *logrus.Logger // Logger for miner-specific logging
	rejectedTxFile *os.File       // File to store information about rejected transactions

	maxBlockSize uint // Maximum allowed block size in weight units
}

// New creates and returns a new miner instance with the given mempool and options.
func New(mempool mempool.Mempool, opts Opts) (*miner, error) {
	file, err := os.OpenFile("../rejected_txs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &miner{
		block: &block.Block{},

		logger:       opts.Logger,
		maxBlockSize: opts.MaxBlockSize,
		mempool:      mempool,

		rejectedTxFile: file,
	}, nil
}

// Mine performs the block building and mining process.
// It selects transactions from the mempool, constructs the block,
// creates a coinbase transaction, and mines the block to meet the target difficulty.
func (m *miner) Mine() error {
	weight := 0
	feeCollected := 0
	wTxids := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
	}

	GivenDifficulty := HexMustDecode("0000ffff00000000000000000000000000000000000000000000000000000000")

	//TODO: use logrus file than file writing
PICK_TX:
	for weight < config.MAX_BLOCK_SIZE {
		tx, err := m.mempool.PickBestTx()
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				m.logger.Info("mempool is empty")
				break PICK_TX
			}
			return err
		}

		if weight+int(tx.Weight) > config.MAX_BLOCK_SIZE {
			tx, err = m.mempool.PickBestTxWithinWeight(uint64(config.MAX_BLOCK_SIZE - weight))
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					m.logger.Info("mempool is empty")
					break PICK_TX
				}
				return err
			}
		}

		fmt.Printf("\rProcessing... tx: %s collected: %d with weight: %d", tx.Hash, feeCollected, weight)

		inputs, err := m.mempool.GetInputs(tx.Hash)
		if err != nil {
			m.logger.Info("unable to get inputs", err)
			return err
		}

		if err := m.mempool.ValidateWholeTx(tx, inputs); err != nil {
			m.logger.Infof("tx is invalid %s", err)
			m.rejectedTxFile.WriteString(tx.Hash + " Reason: Invalid tx" + "\n")
			continue PICK_TX
		}

		// signature checks and stack execution
		for _, input := range inputs {
			if err := m.mempool.MarkOutPointSpent(input.FundingTxHash, input.FundingIndex); err != nil {
				if errors.Is(err, ierrors.ErrAlreadySpent) {
					m.logger.Info("already spent")
					m.rejectedTxFile.WriteString(tx.Hash + " Reason: Already spent" + "\n")
					continue PICK_TX
				}
			}
		}

		if err := m.mempool.DeleteTx(tx.ID); err != nil {
			m.logger.Info("unable to delete tx", err)
			return err
		}

		// include tx in block
		weight += int(tx.Weight)
		// if weight > config.MAX_BLOCK_SIZE {
		// 	m.logger.Info("tx weight is too big")
		// 	weight -= int(tx.Weight)
		// 	break PICK_TX
		// }
		feeCollected += int(tx.FeeCollected)

		m.block.Txs = append(m.block.Txs, tx.Hash) // hash is in LittleEndian
		wTxids = append(wTxids, tx.WTXID)          // wTxid is in LittleEndian
	}

	coinbaseVin := mempool.TxIn{
		Txid:       "0000000000000000000000000000000000000000000000000000000000000000",
		Vout:       0xffffffff,
		ScriptSig:  "0368c10c",
		Sequence:   0xffffffff,
		Witness:    []string{"0000000000000000000000000000000000000000000000000000000000000000"},
		IsCoinbase: true,
	}

	coinbaseVouts := []mempool.TxOut{
		{
			Value:        0,
			ScriptPubKey: "6a24aa21a9ed" + Hash256(GenerateMerkleRoot(wTxids)+"0000000000000000000000000000000000000000000000000000000000000000"),
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
		return err
	}

	m.block.Txs = append([]string{cbTxId}, m.block.Txs...)

	blockHeader := block.BlocKHeader{
		Version:           4,
		TimeStamp:         uint32(time.Now().Unix()),
		NBits:             0x1f00ffff,
		PreviousBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Nonce:             0,
		MerkleRoot:        reverseStringByteOrder(GenerateMerkleRoot(m.block.Txs)),
	}

	respChan := make(chan uint32)
	doneChan := make(chan struct{})

	// spin 10 go routines which listen for nonces
	// after receiving nonces they build block header and send as response
	nextNonce := uint32(0)
	for i := 0; i < 10; i++ {
		go func(blockHeader block.BlocKHeader) {
			for {
				select {
				case <-doneChan:
					return
				default:
					blockHeader.Nonce = atomic.AddUint32(&nextNonce, 1)
					blockHash := doubleHash(blockHeader.Serialize())
					if bytes.Compare(reverseByteOrder(blockHash), GivenDifficulty) < 0 {
						m.logger.Infof("\nNonce :- %d hash is %s", blockHeader.Nonce, hex.EncodeToString(blockHash))
						respChan <- blockHeader.Nonce
						return
					}
				}
			}
		}(blockHeader)
	}

	// wait for nonces
	nonce := <-respChan
	close(doneChan)
	blockHeader.Nonce = nonce
	m.logger.Infof("Nonce: %d hash is %s", blockHeader.Nonce, hex.EncodeToString(doubleHash(blockHeader.Serialize())))

	os.Remove(path.OutFilePath)

	// open output.txt file and write blockHeader serialized , coinbase serialized , txids
	file, err := os.OpenFile(path.OutFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, cb_w_ser, _, err := coinbaseTx.Serialize()
	if err != nil {
		return err
	}

	file.WriteString(hex.EncodeToString(blockHeader.Serialize()) + "\n")
	file.WriteString(hex.EncodeToString(cb_w_ser) + "\n")
	for _, txId := range m.block.Txs {
		file.WriteString(reverseStringByteOrder(txId) + "\n")
	}

	m.logger.Infof("\n mined block %d ", blockHeader.Nonce)
	m.logger.Infof("Total Fee Collected %d \n", feeCollected)
	m.logger.Infof("Total weight %d", weight)

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
