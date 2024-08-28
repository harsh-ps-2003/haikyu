package block

import (
	"encoding/hex"
	"haikyu/pkg/encoding"
)

type BlocKHeader struct {
	Version           uint32 `json:"version"`
	TimeStamp         uint32 `json:"timestamp"`
	NBits             uint32 `json:"bits"`
	Nonce             uint32 `json:"nonce"`
	PreviousBlockHash string `json:"previousblockhash"`
	MerkleRoot        string `json:"merkleroot"`
}

type Block struct {
	Header BlocKHeader `json:"header"`
	Txs    []string    `json:"txs"`
}

func (bh *BlocKHeader) Serialize() []byte {
	serializedHeader := encoding.NewLEBuffer()

	serializedHeader.Set(bh.Version)
	serializedHeader.SetBytes(HexMustDecode(bh.PreviousBlockHash), true)
	serializedHeader.SetBytes(HexMustDecode(bh.MerkleRoot), true)
	serializedHeader.Set(bh.TimeStamp)
	serializedHeader.Set(bh.NBits)
	serializedHeader.Set(bh.Nonce)

	return serializedHeader.GetBuffer()
}

func HexMustDecode(hexStr string) []byte {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return b
}
