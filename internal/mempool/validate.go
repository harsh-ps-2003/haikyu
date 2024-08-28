package mempool

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"haikyu/internal/ierrors"
	"haikyu/pkg/encoding"
	"haikyu/pkg/opcode"
	"haikyu/pkg/transaction"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"golang.org/x/crypto/ripemd160"
)

func (t *Transaction) ValidateTxScripts() error {
	// iter through inputs and validate each one of em based on their type
	for i, input := range t.Vin {
		var err error = nil
		switch transaction.Type(input.Prevout.ScriptPubKeyType) {
		case transaction.OP_RETURN_TYPE:
			err = ierrors.ErrUsingOpReturnAsInput
		case transaction.P2PK:
			err = nil // ignore for now no p2pk txs in assignment
		case transaction.P2PKH:

			tempTx := *t

			stackElem := strings.Split(input.ScriptSigAsm, " ")

			// compressed pubkey
			pubKey := stackElem[len(stackElem)-1]
			Signature := stackElem[1]

			signatureBytes := MustHexDecode(Signature)
			lastSigByte := signatureBytes[len(signatureBytes)-1]

			MessageHash := generateMessageHashLegacy(tempTx, i, input, lastSigByte)

			err = ECVerify(MessageHash, signatureBytes, MustHexDecode(pubKey))

		case transaction.P2SH:
			redeemScript := MustDecodeAsmScript(strings.Split(input.InnerRedeemScriptAsm, " "))
			redeemScripExpectedtHash := strings.Split(input.Prevout.ScriptPubKeyAsm, " ")[2]

			if hex.EncodeToString(H160(redeemScript)) != redeemScripExpectedtHash {
				err = ierrors.ErrRedeemScriptMismatch
			}

		case transaction.P2MS:
			err = nil

		case transaction.P2WSH:
			redeemScript := MustDecodeAsmScript(strings.Split(input.InnerWitnessScriptAsm, " "))
			redeemScripExpectedtHash := strings.Split(input.Prevout.ScriptPubKeyAsm, " ")[2]

			if hex.EncodeToString(Sha256(redeemScript)) != redeemScripExpectedtHash {
				err = ierrors.ErrRedeemScriptMismatch
			}

		case transaction.P2WPKH:
			tempTx := *t

			if (len(input.Witness)) != 2 {
				err = ierrors.ErrInvalidWitnessLength
				break
			}

			Signature := MustHexDecode(input.Witness[0])
			pubKeyHash := MustHexDecode(input.Witness[1])

			lastSigByte := Signature[len(Signature)-1]

			MessageHash := generateMessageHashSegwit(tempTx, i, input, lastSigByte)

			err = ECVerify(MessageHash, Signature, pubKeyHash)

		case transaction.P2TR:
			err = nil
		default:
			err = ierrors.ErrScriptValidation
		}
		if err != nil {
			fmt.Printf("\n encountered an error: %s for inputTxid: %s and vout number: %d", err, input.Txid, input.Vout)
			return err
		}
	}
	return nil
}

// verifies ecdsa signature from der encoding
// digest MessageHash Signed
// sig: signature with r and s in DER encoding
// pubkey: compressed 33 byte pubkey
func ECVerify(digest []byte, sig []byte, pubkey []byte) error {
	signature, err := ecdsa.ParseDERSignature(sig)
	if err != nil {
		return err
	}

	publicKey, err := btcec.ParsePubKey(pubkey)
	if err != nil {
		return err
	}

	if !signature.Verify(digest, publicKey) {
		// fmt.Printf("signature: %s\n and pubkey: %s", hex.EncodeToString(signature.Serialize()), hex.EncodeToString(publicKey.SerializeUncompressed()))
		return ierrors.ErrInvalidSignature
	}
	return nil
}

func MustHexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func MustDecodeAsmScript(asmScript []string) []byte {
	decoded_script := []byte{}
	for _, item := range asmScript {
		if len(item) > 3 && item[:3] == "OP_" {
			byteCode, ok := opcode.OpCodeMap[item]
			if !ok {
				panic("invalid opcode: " + item)
			}
			decoded_script = append(decoded_script, byteCode)
			continue
		}

		byteItem, _ := hex.DecodeString(item)

		decoded_script = append(decoded_script, byteItem...)
	}
	return decoded_script
}

func H160(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	firstHash := h.Sum(nil)

	h = ripemd160.New()
	h.Write(firstHash)

	return h.Sum(nil)
}

func Sha256(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

func generateMessageHashLegacy(tempTx Transaction, i int, input TxIn, sigHash byte) []byte {
	var serializedTx []byte

	switch sigHash {
	case 0x01: // sighashAll
		for j := 0; j < len(tempTx.Vin); j++ {
			tempTx.Vin[j].ScriptSig = ""
		}
		tempTx.Vin[i].ScriptSig = input.Prevout.ScriptPubKey
		serializedTx = tempTx.MustSerializeWithSigHashAll()
	case 0x81:
		tempTx.Vin = []TxIn{input}
		tempTx.Vin[0].ScriptSig = input.Prevout.ScriptPubKey
		serializedTx = tempTx.MustSerializeWithSigHashAnyOneCanPaySigHashAll()
	default:
		for j := 0; j < len(tempTx.Vin); j++ {
			tempTx.Vin[j].ScriptSig = ""
		}
		tempTx.Vin[i].ScriptSig = input.Prevout.ScriptPubKey
		serializedTx = tempTx.MustSerializeWithSigHashAll()
	}

	return chainhash.DoubleHashB(serializedTx)
}

func generateMessageHashSegwit(tempTx Transaction, pos int, input TxIn, sigHash byte) []byte {
	var serializedTx []byte
	switch sigHash {
	case 0x01:
		serializedTx = SegwitSerializeAll(tempTx, input, []byte{0x01, 0x00, 0x00, 0x00})
	case 0x81:
		// tempTx.Vin = []TxIn{input}
		// tempTx.Vin[0].ScriptSig = input.Prevout.ScriptPubKey
		serializedTx = SegwitSerializeAllAnyOne(tempTx, input, []byte{0x81, 0x00, 0x00, 0x00})
	case 0x83:
		serializedTx = SegwitSerializeSingleAnyOne(tempTx, pos, input, []byte{0x83, 0x00, 0x00, 0x00})
	default:
		serializedTx = SegwitSerializeAll(tempTx, input, []byte{0x01, 0x00, 0x00, 0x00})
	}
	if tempTx.Vin[0].Txid == "f3898029a8699bd8b71dc6f20e7ec2762a945a30d6a9f18034ce92a9d6cdd26c" {
		fmt.Println("serializedTx", serializedTx)
	}
	return chainhash.DoubleHashB(serializedTx)
}

// returns pre image
// preimage = version ✅ + hash256(inputs) ✅ + hash256(sequences) ✅ + input ✅ + scriptcode ✅ + amount ✅ + sequence ✅ + hash256(outputs) + locktime ✅ + SIGHASH ✅
func SegwitSerializeAll(tempTx Transaction, inp TxIn, sigHash []byte) []byte {
	preImage := encoding.NewLEBuffer()

	preImage.Set(tempTx.Version)

	InputsBytes := encoding.NewLEBuffer()
	SequencesBytes := encoding.NewLEBuffer()

	for _, input := range tempTx.Vin {
		InputsBytes.SetBytes(MustHexDecode(input.Txid), true)
		InputsBytes.Set(input.Vout)

		SequencesBytes.Set(input.Sequence)
	}

	preImage.SetBytes(chainhash.DoubleHashB(InputsBytes.GetBuffer()), false)
	preImage.SetBytes(chainhash.DoubleHashB(SequencesBytes.GetBuffer()), false)

	preImage.SetBytes(MustHexDecode(inp.Txid), true)
	preImage.Set(inp.Vout)

	pubKeyHash := MustHexDecode(inp.Prevout.ScriptPubKey[4:])

	scriptCode := make([]byte, 0)
	scriptCode = append(scriptCode, []byte{
		0x19, 0x76, 0xa9, 0x14,
	}...)
	scriptCode = append(scriptCode, pubKeyHash...)
	scriptCode = append(scriptCode, 0x88, 0xac)

	preImage.SetBytes(scriptCode, false)
	preImage.Set(inp.Prevout.Value)
	preImage.Set(inp.Sequence)

	outputBytes := encoding.NewLEBuffer()

	for _, output := range tempTx.Vout {
		outputBytes.Set(output.Value)
		scriptPubKey := MustHexDecode(output.ScriptPubKey)
		outputBytes.Set(encoding.CompactSize(uint64(len(scriptPubKey))))
		outputBytes.SetBytes(scriptPubKey, false)
	}

	preImage.SetBytes(chainhash.DoubleHashB(outputBytes.GetBuffer()), false)
	preImage.Set(tempTx.Locktime)

	preImage.SetBytes(sigHash, false) // sighash
	return preImage.GetBuffer()
}

func SegwitSerializeAllAnyOne(tempTx Transaction, inp TxIn, sigHash []byte) []byte {
	preImage := encoding.NewLEBuffer()

	preImage.Set(tempTx.Version)

	preImage.SetBytes(MustHexDecode("0000000000000000000000000000000000000000000000000000000000000000"), false) // hashPrevouts
	preImage.SetBytes(MustHexDecode("0000000000000000000000000000000000000000000000000000000000000000"), false) // hashSequence

	preImage.SetBytes(MustHexDecode(inp.Txid), true)
	preImage.Set(inp.Vout)

	pubKeyHash := MustHexDecode(inp.Prevout.ScriptPubKey[4:])

	scriptCode := make([]byte, 0)
	scriptCode = append(scriptCode, []byte{
		0x19, 0x76, 0xa9, 0x14,
	}...)

	scriptCode = append(scriptCode, pubKeyHash...)
	scriptCode = append(scriptCode, 0x88, 0xac)

	preImage.SetBytes(scriptCode, false)
	preImage.Set(inp.Prevout.Value)
	preImage.Set(inp.Sequence)

	outputBytes := encoding.NewLEBuffer()

	for _, output := range tempTx.Vout {
		outputBytes.Set(output.Value)
		scriptPubKey := MustHexDecode(output.ScriptPubKey)
		outputBytes.Set(encoding.CompactSize(uint64(len(scriptPubKey))))
		outputBytes.SetBytes(scriptPubKey, false)
	}

	preImage.SetBytes(chainhash.DoubleHashB(outputBytes.GetBuffer()), false)
	preImage.Set(tempTx.Locktime)

	preImage.SetBytes(sigHash, false) // sighash

	return preImage.GetBuffer()
}

func SegwitSerializeSingleAnyOne(tempTx Transaction, pos int, inp TxIn, sigHash []byte) []byte {
	preImage := encoding.NewLEBuffer()

	preImage.Set(tempTx.Version)

	preImage.SetBytes(MustHexDecode("0000000000000000000000000000000000000000000000000000000000000000"), false) // hashPrevouts
	preImage.SetBytes(MustHexDecode("0000000000000000000000000000000000000000000000000000000000000000"), false) // hashSequence

	preImage.SetBytes(MustHexDecode(inp.Txid), true)
	preImage.Set(inp.Vout)

	pubKeyHash := MustHexDecode(inp.Prevout.ScriptPubKey[4:])

	scriptCode := make([]byte, 0)
	scriptCode = append(scriptCode, []byte{
		0x19, 0x76, 0xa9, 0x14,
	}...)

	scriptCode = append(scriptCode, pubKeyHash...)
	scriptCode = append(scriptCode, 0x88, 0xac)

	preImage.SetBytes(scriptCode, false)
	preImage.Set(inp.Prevout.Value)
	preImage.Set(inp.Sequence)

	outputBytes := encoding.NewLEBuffer()

	output := tempTx.Vout[pos]

	outputBytes.Set(output.Value)
	scriptPubKey := MustHexDecode(output.ScriptPubKey)
	outputBytes.Set(encoding.CompactSize(uint64(len(scriptPubKey))))
	outputBytes.SetBytes(scriptPubKey, false)

	preImage.SetBytes(chainhash.DoubleHashB(outputBytes.GetBuffer()), false)
	preImage.Set(tempTx.Locktime)

	preImage.SetBytes(sigHash, false) // sighash

	return preImage.GetBuffer()
}
