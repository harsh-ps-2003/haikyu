package mempool

import (
	"encoding/hex"
	"haikyu/internal/ierrors"
	"haikyu/pkg/address"
	"haikyu/pkg/opcode"
	"haikyu/pkg/transaction"
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type mempool struct {
	dust           uint64
	maxTxSize      uint
	maxMemPoolSize uint
	db             *gorm.DB
	logger         *logrus.Logger
	mu             sync.RWMutex
	rejectedTxFile *os.File
}

type Mempool interface {
	DB() *gorm.DB
	ResetTables() error

	PutTx(tx Transaction) error
	PickBestTx() (transaction.Tx, error)
	PickBestTxWithinWeight(weight uint64) (transaction.Tx, error)
	DeleteTx(ID uint) error

	GetInputs(SpendingTxHash string) ([]transaction.InputTx, error)
	GetOutputs(FundingTxHash string) ([]transaction.OutPutTx, error)
	GetOutPointByIndex(FundingTxHash string, index uint32) (transaction.OutPutTx, error)

	MarkOutPointSpent(FundingTxHash string, index uint32) error
	ValidateWholeTx(tx transaction.Tx, inputs []transaction.InputTx) error
}

func New(dialector gorm.Dialector, mempoolOpts Opts, opts ...gorm.Option) (Mempool, error) {
	db, err := gorm.Open(dialector, opts...)
	if err != nil {
		return nil, err

	}

	if err := db.AutoMigrate(transaction.Tx{}, transaction.InputTx{}, transaction.OutPutTx{}); err != nil {
		return nil, err
	}

	var _tx transaction.Tx
	stmt := db.Session(&gorm.Session{DryRun: true}).Order("fee_collected / weight desc").Limit(1).Find(&_tx).Limit(1).Statement
	if err := db.Order("fee_collected / weight desc").Find(&_tx).Limit(1).Error; err != nil {
		return nil, err
	}
	mempoolOpts.Logger.Infof("Dry Run Test: %v", stmt.SQL.String())
	mempoolOpts.Logger.Infof("Dry Run Test: %v", _tx)

	return &mempool{
		db:     db,
		logger: mempoolOpts.Logger,

		maxMemPoolSize: mempoolOpts.MaxMemPoolSize,

		dust:      mempoolOpts.Dust,
		maxTxSize: mempoolOpts.MaxTxSize,

		mu: sync.RWMutex{},

		// rejectedTxFile: ,
	}, nil
}

func (m *mempool) DB() *gorm.DB {
	return m.db
}

// TODO: configure proper logger
func (m *mempool) PutTx(tx Transaction) error {

	if err := tx.Validate(); err != nil {
		m.logger.Info("tx id is invalid ", err)
		return err
	}

	txHash, wtxid, weight, err := tx.Hash()
	if err != nil {
		m.logger.Info("unable to compute Hash", err)
		return err
	}

	_tx := transaction.Tx{
		Version:  tx.Version,
		Locktime: tx.Locktime,
		Hash:     txHash,
		Weight:   uint64(weight),
		WTXID:    wtxid,
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	amountLoad, err := m.PutInputTx(tx.Vin, txHash)
	if err != nil {
		m.logger.Info("unable to PutInputTx", err)
		return err
	}

	amountSpent, err := m.PutOutputTx(tx.Vout, []string{txHash}, []uint32{})
	if err != nil {
		m.logger.Infof("unable to PutOutputTx %v for tx %v", err, txHash)
		return err
	}

	feeCollected := amountLoad - amountSpent

	if feeCollected < int(m.dust) {
		m.logger.Info("fee collected is less than dust")
		return ierrors.ErrFeeTooLow
	}

	_tx.FeeCollected = uint64(feeCollected)
	return m.db.Create(&_tx).Error
}

// TODO: batch writes to db
func (m *mempool) PutInputTx(Vin []TxIn, spendingHash string) (amountLoaded int, err error) {

	outputs := []TxOut{}

	fundingTxIndexes := []uint32{}
	fundingTxHashes := []string{}

	inputTxs := []transaction.InputTx{}

	isRBF := false

	for i := 0; i < len(Vin); i++ {
		witness := ""
		for j := 0; j < len(Vin[i].Witness); j++ {
			if j != 0 {
				witness += ","
			}
			witness += Vin[i].Witness[j]
		}

		inputTx := transaction.InputTx{
			SpendingTxHash: spendingHash,

			FundingTxHash: Vin[i].Txid,
			FundingIndex:  Vin[i].Vout,

			ScriptSig: Vin[i].ScriptSig,
			Sequence:  Vin[i].Sequence,
			ScriptAsm: Vin[i].ScriptSigAsm,
			Witness:   witness,

			IsCoinbase: Vin[i].IsCoinbase, // no coinbase txs in given mempool [might remove in future iterations]

			InnerWitnessScriptAsm: Vin[i].InnerWitnessScriptAsm,
			InnerRedeemScriptAsm:  Vin[i].InnerRedeemScriptAsm,
		}

		inputTxs = append(inputTxs, inputTx)

		outputs = append(outputs, Vin[i].Prevout)
		fundingTxIndexes = append(fundingTxIndexes, Vin[i].Vout)
		fundingTxHashes = append(fundingTxHashes, Vin[i].Txid)

		if Vin[i].Sequence <= 0xFFFFFFFD && !isRBF {
			isRBF = true
		}
	}

	if err := m.db.Create(&inputTxs).Error; err != nil {
		m.logger.Info("unable to create input txs", err)
		return 0, err
	}

	amountLoaded, err = m.PutOutputTx(outputs, fundingTxHashes, fundingTxIndexes)
	if err != nil {
		m.logger.Infof("unable to PutOutputTx %v for tx %v", err, spendingHash)
		return 0, err
	}

	return amountLoaded, nil
}

// TODO: batch writes to db
func (m *mempool) PutOutputTx(Vout []TxOut, fundingTxHashes []string, fundingIndexes []uint32) (amountSpent int, err error) {
	amountSpent = 0

	if len(fundingIndexes) == 0 {
		for i := 0; i < len(Vout); i++ {
			fundingIndexes = append(fundingIndexes, uint32(i))
		}
	}

	if len(fundingTxHashes) == 1 {
		for i := 1; i < len(Vout); i++ {
			fundingTxHashes = append(fundingTxHashes, fundingTxHashes[0])
		}
	}

	if len(Vout) != len(fundingIndexes) {
		m.logger.Info("len(Vout) != len(fundingIndexes)")
		return 0, ierrors.ErrInvalidTx
	}

	for i := 0; i < len(Vout); i++ {
		amountSpent += int(Vout[i].Value)

		outPutTx := transaction.OutPutTx{
			FundingTxHash: fundingTxHashes[i],
			FundingTxPos:  uint32(fundingIndexes[i]),
			ScriptPubKey:  Vout[i].ScriptPubKey,
			ScriptAsm:     Vout[i].ScriptPubKeyAsm,
			ScriptType:    transaction.Type(Vout[i].ScriptPubKeyType),
			ScriptAddress: Vout[i].ScriptPubKeyAddress,
			Value:         Vout[i].Value,
		}

		if err := m.ValidateOutput(outPutTx); err != nil {
			m.logger.Info("unable to ValidateOutput", err)
			return 0, err
		}

		var tempOut transaction.OutPutTx

		// check if outpoint already exists in db by fundingTxHash and index
		if err := m.db.Where("funding_tx_hash = ? AND funding_tx_pos = ?", outPutTx.FundingTxHash, fundingIndexes[i]).Take(&tempOut).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				if err := m.db.Create(&outPutTx).Error; err != nil {
					m.logger.Info("unable to create outpoint tx", err)
					return 0, err
				}
				continue
			}

			m.logger.Info("err while fetching outpoint from db", err)
			return 0, err
		}

		m.logger.Debugf("outpoint %s:%d already exists in db ID %d obj %v and err %v", outPutTx.FundingTxHash, fundingIndexes[i], tempOut.ID, tempOut, err)
		continue
	}

	return amountSpent, nil
}

func (m *mempool) PickBestTx() (transaction.Tx, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var _tx transaction.Tx

	if err := m.db.Order("fee_collected / weight desc").Find(&_tx).Limit(1).Error; err != nil {
		return transaction.Tx{}, err
	}

	return _tx, nil
}

func (m *mempool) GetInputs(SpendingTxHash string) ([]transaction.InputTx, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var inputs []transaction.InputTx
	if err := m.db.Where("spending_tx_hash = ?", SpendingTxHash).Find(&inputs).Error; err != nil {
		return nil, err
	}

	return inputs, nil
}

func (m *mempool) GetOutputs(FundingTxHash string) ([]transaction.OutPutTx, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var outputs []transaction.OutPutTx
	if err := m.db.Where("funding_tx_hash = ?", FundingTxHash).Find(&outputs).Error; err != nil {
		return nil, err
	}

	return outputs, nil
}

func (m *mempool) GetOutPointByIndex(FundingTxHash string, index uint32) (transaction.OutPutTx, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var output transaction.OutPutTx
	if err := m.db.Where("funding_tx_hash = ? AND funding_tx_pos = ?", FundingTxHash, index).Find(&output).Error; err != nil {
		return transaction.OutPutTx{}, err
	}

	return output, nil
}

func (m *mempool) MarkOutPointSpent(FundingTxHash string, index uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var output transaction.OutPutTx
	if err := m.db.Where("funding_tx_hash = ? AND funding_tx_pos = ?", FundingTxHash, index).Find(&output).Error; err != nil {
		return err
	}

	if output.Spent {
		m.logger.Info("outpoint already spent", FundingTxHash, index)
		return ierrors.ErrAlreadySpent
	}

	output.Spent = true
	if err := m.db.Save(&output).Error; err != nil {
		return err
	}

	return nil
}

// UnUsed
func (m *mempool) ValidateInput(input transaction.InputTx) error {

	// TODO: validate sequence only if tx version is 2
	if input.Sequence > 0xffffffff {
		return ierrors.ErrInvalidSequence
	}

	prevOut, err := m.GetOutPointByIndex(input.FundingTxHash, input.FundingIndex)
	if err != nil {
		m.logger.Info("err while fetching outpoint from db", err)
		return err
	}

	switch prevOut.ScriptType {
	case transaction.OP_RETURN_TYPE:
		return ierrors.ErrUsingOpReturnAsInput
	case transaction.P2MS:
	case transaction.P2PKH,
		transaction.P2WPKH, transaction.P2WSH,
		transaction.P2TR, transaction.P2PK, transaction.P2SH:
	default:
		m.logger.Info("invalid script type", prevOut.ScriptType)
		return ierrors.ErrInvalidScript
	}

	return nil
}

func (m *mempool) ValidateOutput(out transaction.OutPutTx) error {

	if out.ScriptType == transaction.OP_RETURN_TYPE {
		return nil
	}

	if out.ScriptAsm == "" {
		return nil
	}
	asmScript := strings.Split(out.ScriptAsm, " ")

	decoded_script := []byte{}
	for _, item := range asmScript {
		if len(item) > 3 && item[:3] == "OP_" {
			bytedecoded, ok := opcode.OpCodeMap[item]
			if !ok {
				m.logger.Info("invalid opcode", item, out.ScriptAddress)
				return ierrors.ErrInvalidOpCode
			}
			decoded_script = append(decoded_script, bytedecoded)
			continue
		}

		byteItem, err := hex.DecodeString(item)
		if err != nil {
			m.logger.Info("invalid hex string", " "+item+" ", err, " "+out.ScriptAddress)
			return err
		}

		decoded_script = append(decoded_script, byteItem...)
	}

	hexstring := hex.EncodeToString(decoded_script)
	if hexstring != out.ScriptPubKey {
		m.logger.Infof("asm and script mismatch %v %v", hexstring, out.ScriptPubKey)
		return ierrors.ErrAsmAndScriptMismatch
	}

	encodedAddress, err := address.EncodeAddress(out.ScriptAsm, out.ScriptType)
	if err != nil {
		m.logger.Infof("unable to encode address %v for script %v", err, out.ScriptAsm)
		return err
	}

	if encodedAddress != out.ScriptAddress {
		m.logger.Info("asm and address mismatch", encodedAddress, out.ScriptAddress)
		return ierrors.ErrInvalidAddress
	}

	return nil
}

func (m *mempool) DeleteTx(ID uint) error {
	return m.db.Delete(&transaction.Tx{}, ID).Error
}

func (m *mempool) ValidateWholeTx(tx transaction.Tx, inputs []transaction.InputTx) error {

	m.mu.RLock()
	defer m.mu.RUnlock()

	var Vins []TxIn
	var Vouts []TxOut

	for _, input := range inputs {
		outpoint, err := m.GetOutPointByIndex(input.FundingTxHash, input.FundingIndex)
		if err != nil {
			return err
		}

		Vins = append(Vins, TxIn{
			Txid: input.FundingTxHash,
			Vout: input.FundingIndex,
			Prevout: TxOut{
				ScriptPubKey:        outpoint.ScriptPubKey,
				ScriptPubKeyAsm:     outpoint.ScriptAsm,
				ScriptPubKeyType:    string(outpoint.ScriptType),
				ScriptPubKeyAddress: outpoint.ScriptAddress,
				Value:               outpoint.Value,
			},
			ScriptSig:    input.ScriptSig,
			ScriptSigAsm: input.ScriptAsm,
			Witness:      strings.Split(input.Witness, ","),
			Sequence:     input.Sequence,

			InnerWitnessScriptAsm: input.InnerWitnessScriptAsm,
			InnerRedeemScriptAsm:  input.InnerRedeemScriptAsm,
		})
	}

	outputs, err := m.GetOutputs(tx.Hash)
	if err != nil {
		return err
	}

	for _, output := range outputs {
		Vouts = append(Vouts, TxOut{
			ScriptPubKey:        output.ScriptPubKey,
			ScriptPubKeyAsm:     output.ScriptAsm,
			ScriptPubKeyType:    string(output.ScriptType),
			ScriptPubKeyAddress: output.ScriptAddress,
			Value:               output.Value,
		})
	}

	wholeTx := Transaction{
		Version:  tx.Version,
		Locktime: tx.Locktime,
		Vin:      Vins,
		Vout:     Vouts,
	}

	return wholeTx.ValidateTxScripts()
}

func (m *mempool) ResetTables() error {
	if err := m.db.Exec("UPDATE txes SET deleted_at = NULL;").Error; err != nil {
		return err
	}

	if err := m.db.Exec("UPDATE out_put_txes SET spent = false;").Error; err != nil {
		return err
	}

	return nil
}

func (m *mempool) PickBestTxWithinWeight(weight uint64) (transaction.Tx, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var _tx transaction.Tx
	if err := m.db.Where("weight <= ?", weight).Order("fee_collected / weight desc").Take(&_tx).Limit(1).Error; err != nil {
		return transaction.Tx{}, err
	}

	return _tx, nil
}
