package mempool

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"haikyu/internal/ierrors"
	en "haikyu/pkg/encoding"
	"reflect"
	"strings"
)

var (
	TX_PARAM_MULTIPLIER = 4
	WITNESS_DISCOUNT    = 1
)

type Transaction struct {
	Version  uint32  `json:"version,strict_check"`
	Locktime uint32  `json:"locktime"`
	Vin      []TxIn  `json:"vin,strict_check"`
	Vout     []TxOut `json:"vout,strict_check"`
}

type TxIn struct {
	Txid         string   `json:"txid,strict_check"`
	Vout         uint32   `json:"vout"`
	Prevout      TxOut    `json:"prevout,strict_check"`
	ScriptSig    string   `json:"scriptsig"`
	ScriptSigAsm string   `json:"scriptsig_asm"`
	Witness      []string `json:"witness"`
	IsCoinbase   bool     `json:"is_coinbase"`
	Sequence     uint32   `json:"sequence"`

	InnerWitnessScriptAsm string `json:"inner_witnessscript_asm"`
	InnerRedeemScriptAsm  string `json:"inner_redeemscript_asm"`
}

type TxOut struct {
	ScriptPubKey        string `json:"scriptpubkey"`
	ScriptPubKeyAsm     string `json:"scriptpubkey_asm"`
	ScriptPubKeyType    string `json:"scriptpubkey_type"`
	ScriptPubKeyAddress string `json:"scriptpubkey_address"`
	Value               uint64 `json:"value"`
}

// TODO: add additional sanity checks
func (t *Transaction) Validate() error {
	if Validate(*t) == nil {
		for i := 0; i < len(t.Vin); i++ {
			if err := Validate(t.Vin[i]); err != nil {
				return ierrors.ErrInvalidTx
			}
		}

		for i := 0; i < len(t.Vout); i++ {
			if err := Validate(t.Vout[i]); err != nil {
				return ierrors.ErrInvalidTx
			}
		}
		return nil
	}
	return ierrors.ErrInvalidTx
}

func (t *Transaction) Hash() (string, string, int, error) {
	serializedTx, serializedWitnessTx, weight, err := t.Serialize()
	if err != nil {
		return "", "", 0, err
	}

	return doubleHash(serializedTx), doubleHash(serializedWitnessTx), weight, nil
}

func doubleHash(item []byte) string {
	h := sha256.New()
	h.Write(item)
	firstHash := h.Sum(nil)

	h.Reset()
	h.Write(firstHash)

	return hex.EncodeToString(h.Sum(nil))
}

func (t *Transaction) Fee() uint64 {
	var fee uint64
	for _, vin := range t.Vin {
		fee += vin.Prevout.Value
	}
	for _, vout := range t.Vout {
		fee -= vout.Value
	}
	return fee
}

/*
* Tx:
* version (u32) + inputCount (compactSize)
* + [ fundingTxHash (u256) + voutIndex (u32) + ScriptSigSize (compactSize) + ScriptSig (bytes) + Sequence (u32) ]
* + outputCount (compactSize)
* + [ amount (u64) + ScriptPubKeySize (compactSize) + ScriptPubKey (bytes) ]
* locktime (u32)
 */

func (t *Transaction) Serialize() ([]byte, []byte, int, error) {

	// weight calculation
	weight := 4*TX_PARAM_MULTIPLIER + (1+1)*WITNESS_DISCOUNT // (version * 4) + (Marker * Flag) * 1

	// add version to serialized tx
	serializedTx := en.NewLEBuffer()
	serializedTx.Set(t.Version)

	inputCount := en.CompactSize(uint64(len(t.Vin)))

	serializedTx.SetBytes(inputCount, false)

	weight += len(inputCount) * TX_PARAM_MULTIPLIER

	isSegwit := false

	for i := 0; i < len(t.Vin); i++ {

		fundingTxHash, err := hex.DecodeString(t.Vin[i].Txid)
		if err != nil {
			return nil, nil, 0, ierrors.ErrInvalidTx
		}

		scriptSig, err := hex.DecodeString(t.Vin[i].ScriptSig)
		if err != nil {
			return nil, nil, 0, ierrors.ErrInvalidTx
		}

		scriptSigSize := en.CompactSize(uint64(len(scriptSig)))

		weight += 32 * TX_PARAM_MULTIPLIER // fundingTxHash TxId
		weight += 4 * TX_PARAM_MULTIPLIER  // voutIndex (u32)
		weight += len(scriptSigSize) * TX_PARAM_MULTIPLIER
		weight += len(scriptSig) * TX_PARAM_MULTIPLIER
		weight += 4 * TX_PARAM_MULTIPLIER // Sequence (u32)

		serializedTx.SetBytes(fundingTxHash, true)
		serializedTx.Set(t.Vin[i].Vout)
		serializedTx.SetBytes(scriptSigSize, false)
		serializedTx.SetBytes(scriptSig, false)
		serializedTx.Set(t.Vin[i].Sequence)

		witnessCount := en.CompactSize(uint64(len(t.Vin[i].Witness)))

		weight += len(witnessCount) * WITNESS_DISCOUNT

		for _, witness := range t.Vin[i].Witness {

			witness, err := hex.DecodeString(witness)
			if err != nil {
				return nil, nil, 0, ierrors.ErrInvalidTx
			}

			witnessSize := en.CompactSize(uint64(len(witness)))
			weight += len(witnessSize) * WITNESS_DISCOUNT
			weight += len(witness) * WITNESS_DISCOUNT
		}

		if len(t.Vin[i].Witness) > 0 {
			isSegwit = true
		}
	}

	outputCount := en.CompactSize(uint64(len(t.Vout)))
	weight += len(outputCount) * TX_PARAM_MULTIPLIER

	serializedTx.SetBytes(outputCount, false)

	for i := 0; i < len(t.Vout); i++ {
		scriptPubKey, err := hex.DecodeString(t.Vout[i].ScriptPubKey)
		if err != nil {
			return nil, nil, 0, ierrors.ErrInvalidTx
		}

		scriptPubKeySize := en.CompactSize(uint64(len(scriptPubKey)))

		weight += 8 * TX_PARAM_MULTIPLIER // amount (u64)
		weight += len(scriptPubKeySize) * TX_PARAM_MULTIPLIER
		weight += len(scriptPubKey) * TX_PARAM_MULTIPLIER

		serializedTx.Set(t.Vout[i].Value)
		serializedTx.SetBytes(scriptPubKeySize, false)
		serializedTx.SetBytes(scriptPubKey, false)
	}

	serializedBytes := serializedTx.GetBuffer()

	// add version , mark , flag and witness to serialized Witness tx
	serializedWitnessTx := en.NewLEBuffer()
	// add version serializedBytes to serialized Witness tx
	serializedWitnessTx.SetBytes(serializedBytes[0:4], false)
	serializedWitnessTx.Set(uint8(0))                        // add marker
	serializedWitnessTx.Set(uint8(1))                        // add flag
	serializedWitnessTx.SetBytes(serializedBytes[4:], false) // add rest of inputs and outputs

	// add witness to serialized witness tx
	for _, inp := range t.Vin {
		witnessList := inp.Witness

		// add stack size to serialized witness tx
		serializedWitnessTx.SetBytes(en.CompactSize(uint64(len(witnessList))), false)

		for _, witness := range witnessList {
			witnessBytes, err := hex.DecodeString(witness)
			if err != nil {
				return nil, nil, 0, ierrors.ErrInvalidTx
			}

			serializedWitnessTx.SetBytes(en.CompactSize(uint64(len(witnessBytes))), false)
			serializedWitnessTx.SetBytes(witnessBytes, false)
		}
	}

	weight += 4 * TX_PARAM_MULTIPLIER // locktime (u32)
	serializedTx.Set(t.Locktime)
	serializedWitnessTx.Set(t.Locktime)

	if !isSegwit {
		serializedWitnessTx = serializedTx
	}

	return serializedTx.GetBuffer(), serializedWitnessTx.GetBuffer(), weight, nil
}

func (t *Transaction) MustSerializeWithSigHashAll() []byte {
	serializedTx, _, _, err := t.Serialize()
	if err != nil {
		panic(err)
	}
	serializedTx = append(serializedTx, []byte{0x01, 0x00, 0x00, 0x00}...)
	return serializedTx
}

func (t *Transaction) MustSerializeWithSigHashAnyOneCanPaySigHashAll() []byte {
	serializedTx, _, _, err := t.Serialize()
	if err != nil {
		panic(err)
	}
	serializedTx = append(serializedTx, []byte{0x81, 0x00, 0x00, 0x00}...)
	return serializedTx
}

var strict_check_tag = "strict_check"

func Validate(elem interface{}) error {
	t := reflect.TypeOf(elem)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")
		if tag == "" {
			continue
		}

		if strings.Contains(tag, strict_check_tag) {
			value := reflect.ValueOf(elem).Field(i)
			if isEmpty(value) {
				fieldName := field.Tag.Get("json")
				return fmt.Errorf("field '%s' is required but missing or null in JSON", strings.TrimPrefix(strings.Split(fieldName, ",")[0], "json:"))
			}
		}

	}
	return nil
}

func isEmpty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		return v.IsNil()
	case reflect.Struct:
		return reflect.DeepEqual(v, reflect.Zero(v.Type()))
	case reflect.Slice, reflect.Map, reflect.Array:
		return v.Len() == 0
	case reflect.String:
		return v.Len() == 0
	}
	return false
}
