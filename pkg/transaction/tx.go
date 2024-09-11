package transaction

import (
	"errors"

	"gorm.io/gorm"
)

type Err error

var (
	ErrInvalidSequence = errors.New("invalid sequence number")
)

type Type string

const (
	// legacy
	P2PK  Type = "p2pk"
	P2PKH Type = "p2pkh"
	P2SH  Type = "p2sh"
	P2MS  Type = "unknown"

	// segwit
	P2WPKH Type = "v0_p2wpkh"
	P2WSH  Type = "v0_p2wsh"

	// taproot
	P2TR Type = "v1_p2tr"

	// uffff type
	OP_RETURN_TYPE Type = "op_return"
)

type Tx struct {
	gorm.Model

	Version  uint32 `json:"version"`
	Locktime uint32 `json:"locktime"`

	Hash  string `json:"hash"`
	WTXID string `json:"wtxid"`

	FeeCollected uint64 `json:"feecollected"`
	Weight       uint64 `json:"weight"`
	IsRBFed      bool   `json:"isrbfed"`
}

type InputTx struct {
	gorm.Model

	// transaction which is spending this input
	SpendingTxHash string `json:"spendingtxhash"`

	// previous output txHash
	FundingTxHash string `json:"fundingtxhash"`
	// previous output tx Index
	FundingIndex uint32 `json:"fundingindex"`

	ScriptSig string `json:"scriptsig"`
	ScriptAsm string `json:"scriptasm"`

	Witness string `json:"witness"`

	IsCoinbase bool   `json:"iscoinbase"`
	Sequence   uint32 `json:"sequence"`

	InnerWitnessScriptAsm string `json:"inner_witnessscript_asm"`
	InnerRedeemScriptAsm  string `json:"inner_redeemscript_asm"`
}

type OutPutTx struct {
	gorm.Model

	// transaction which is Funding this output
	FundingTxHash string `json:"fundingtxhash" gorm:"uniqueIndex:fundingtxIndex"`
	FundingTxPos  uint32 `json:"index" gorm:"uniqueIndex:fundingtxIndex"`

	ScriptPubKey  string `json:"scriptpubkey"`
	ScriptAsm     string `json:"scriptasm"`
	ScriptType    Type   `json:"scripttype"`
	ScriptAddress string `json:"scriptaddress"`

	Value uint64 `json:"value"`

	Spent bool `json:"spent"`
}

// sequence number: No need to check for sequence number (Reason: RBF is sorted, since we dont know origin of FundingTx blocks/txs we cant decide on locktime)
func (i *InputTx) Validate() error {
	if i.Sequence > 0xffffffff {
		return ErrInvalidSequence
	}
	return nil
}
