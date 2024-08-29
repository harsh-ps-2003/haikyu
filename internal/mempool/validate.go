package mempool

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"haikyu/internal/ierrors"
	"haikyu/pkg/encoding"
	"haikyu/pkg/opcode"
	"haikyu/pkg/transaction"
	"hash"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"golang.org/x/crypto/ripemd160"
)

// ValidateTxScripts validates the scripts for all inputs in the transaction.
func (t *Transaction) ValidateTxScripts() error {
	for i, input := range t.Vin {
		err := validateInput(t, i, input)
		if err != nil {
			return fmt.Errorf("input %d validation failed: %w", i, err)
		}
	}
	return nil
}

// validateInput validates a single input based on its script type.
func validateInput(t *Transaction, i int, input TxIn) error {
	switch transaction.Type(input.Prevout.ScriptPubKeyType) {
	case transaction.OP_RETURN_TYPE:
		return ierrors.ErrUsingOpReturnAsInput
	case transaction.P2PK:
		return nil // ignore for now no p2pk txs in assignment
	case transaction.P2PKH:
		return validateP2PKH(t, i, input)
	case transaction.P2SH:
		return validateP2SH(input)
	case transaction.P2MS:
		return nil
	case transaction.P2WSH:
		return validateP2WSH(input)
	case transaction.P2WPKH:
		return validateP2WPKH(t, i, input)
	case transaction.P2TR:
		return nil
	default:
		return ierrors.ErrScriptValidation
	}
}

func validateP2PKH(t *Transaction, i int, input TxIn) error {
	stackElem := strings.Split(input.ScriptSigAsm, " ")
	if len(stackElem) < 2 {
		return ierrors.ErrInvalidScriptSig
	}

	pubKey := stackElem[len(stackElem)-1]
	signature := stackElem[1]

	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	lastSigByte := signatureBytes[len(signatureBytes)-1]
	messageHash := generateMessageHashLegacy(*t, i, input, lastSigByte)

	return ECVerify(messageHash, signatureBytes, MustHexDecode(pubKey))
}

func validateP2SH(input TxIn) error {
	redeemScript := MustDecodeAsmScript(strings.Split(input.InnerRedeemScriptAsm, " "))
	redeemScripExpectedtHash := strings.Split(input.Prevout.ScriptPubKeyAsm, " ")[2]

	if hex.EncodeToString(H160(redeemScript)) != redeemScripExpectedtHash {
		return ierrors.ErrRedeemScriptMismatch
	}

	return nil
}

func validateP2WSH(input TxIn) error {
	redeemScript := MustDecodeAsmScript(strings.Split(input.InnerWitnessScriptAsm, " "))
	redeemScripExpectedtHash := strings.Split(input.Prevout.ScriptPubKeyAsm, " ")[2]

	if hex.EncodeToString(Sha256(redeemScript)) != redeemScripExpectedtHash {
		return ierrors.ErrRedeemScriptMismatch
	}

	return nil
}

func validateP2WPKH(t *Transaction, i int, input TxIn) error {
	if (len(input.Witness)) != 2 {
		return ierrors.ErrInvalidWitnessLength
	}

	signature, err := hex.DecodeString(input.Witness[0])
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	pubKeyHash, err := hex.DecodeString(input.Witness[1])
	if err != nil {
		return fmt.Errorf("invalid pubkey hash hex: %w", err)
	}

	lastSigByte := signature[len(signature)-1]
	messageHash := generateMessageHashSegwit(*t, i, input, lastSigByte)

	return ECVerify(messageHash, signature, pubKeyHash)
}

// ECVerify verifies an ECDSA signature.
// digest: MessageHash Signed
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

var sha256Pool = sync.Pool{
	New: func() interface{} {
		return sha256.New()
	},
}

// H160 performs a SHA256 followed by a RIPEMD160 hash on the input.
func H160(b []byte) []byte {
	h := sha256Pool.Get().(hash.Hash)
	defer sha256Pool.Put(h)
	h.Reset()
	h.Write(b)
	firstHash := h.Sum(nil)

	h160 := ripemd160.New()
	h160.Write(firstHash)
	return h160.Sum(nil)
}

// Sha256 performs a SHA256 hash on the input.
func Sha256(b []byte) []byte {
	h := sha256Pool.Get().(hash.Hash)
	defer sha256Pool.Put(h)
	h.Reset()
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

// SegwitSerializeAll generates the preimage for SegWit transactions with SIGHASH_ALL.
func SegwitSerializeAll(tempTx Transaction, inp TxIn, sigHash []byte) []byte {
	preImage := encoding.NewLEBuffer()
	preImage.Set(tempTx.Version)

	preImage.SetBytes(hashPrevouts(tempTx.Vin), false)
	preImage.SetBytes(hashSequences(tempTx.Vin), false)

	preImage.SetBytes(MustHexDecode(inp.Txid), true)
	preImage.Set(inp.Vout)

	scriptCode := generateP2WPKHScriptCode(inp)
	preImage.SetBytes(scriptCode, false)
	preImage.Set(inp.Prevout.Value)
	preImage.Set(inp.Sequence)

	preImage.SetBytes(hashOutputs(tempTx.Vout), false)
	preImage.Set(tempTx.Locktime)
	preImage.SetBytes(sigHash, false)

	return preImage.GetBuffer()
}

func hashPrevouts(inputs []TxIn) []byte {
	buffer := encoding.NewLEBuffer()
	for _, input := range inputs {
		buffer.SetBytes(MustHexDecode(input.Txid), true)
		buffer.Set(input.Vout)
	}
	return chainhash.DoubleHashB(buffer.GetBuffer())
}

func hashSequences(inputs []TxIn) []byte {
	buffer := encoding.NewLEBuffer()
	for _, input := range inputs {
		buffer.Set(input.Sequence)
	}
	return chainhash.DoubleHashB(buffer.GetBuffer())
}

func hashOutputs(outputs []TxOut) []byte {
	buffer := encoding.NewLEBuffer()
	for _, output := range outputs {
		buffer.Set(output.Value)
		scriptPubKey := MustHexDecode(output.ScriptPubKey)
		buffer.Set(encoding.CompactSize(uint64(len(scriptPubKey))))
		buffer.SetBytes(scriptPubKey, false)
	}
	return chainhash.DoubleHashB(buffer.GetBuffer())
}

func generateP2WPKHScriptCode(inp TxIn) []byte {
	pubKeyHash := MustHexDecode(inp.Prevout.ScriptPubKey[4:])
	scriptCode := make([]byte, 0, 25)
	scriptCode = append(scriptCode, 0x19, 0x76, 0xa9, 0x14)
	scriptCode = append(scriptCode, pubKeyHash...)
	scriptCode = append(scriptCode, 0x88, 0xac)
	return scriptCode
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
