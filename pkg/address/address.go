package address

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"haikyu/internal/ierrors"
	"haikyu/pkg/transaction"
	"strings"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

// encodes given script into address
func EncodeAddress(scriptAsm string, script_type transaction.Type) (string, error) {

	script := strings.Split(scriptAsm, " ")
	if len(script) == 0 {
		return "", errors.New("invalid script")
	}

	switch script_type {
	case transaction.P2PK:
		if len(script) != 3 {
			return "", ierrors.ErrInvalidScript
		}
		pubkey, err := hex.DecodeString(script[1])
		if err != nil {
			return "", ierrors.ErrInvalidScript
		}
		return NewPayToPubKey(pubkey, script[0] == "OP_PUSHBYTES_33" && script[2] == "OP_CHECKSIG")
	case transaction.P2PKH:
		if len(script) != 6 {
			return "", ierrors.ErrInvalidScript
		}

		pubkeyHash, err := hex.DecodeString(script[3])
		if err != nil {
			return "", err
		}

		return NewPayToPubKeyHash(pubkeyHash)
	case transaction.P2SH:
		if len(script) != 4 {
			return "", ierrors.ErrInvalidScript
		}

		pubkeyHash, err := hex.DecodeString(script[2])
		if err != nil {
			return "", err
		}

		return NewPayToScriptHashFromScriptHash(pubkeyHash)
	case transaction.P2WPKH:
		if len(script) != 3 {
			return "", ierrors.ErrInvalidScript
		}

		pubkeyHash, err := hex.DecodeString(script[2])
		if err != nil {
			return "", err
		}

		return NewPayToWitnessPubKeyHash(pubkeyHash)
	case transaction.P2WSH:
		if len(script) != 3 {
			return "", ierrors.ErrInvalidScript
		}

		scriptHash, err := hex.DecodeString(script[2])
		if err != nil {
			return "", err
		}

		return NewPayToWitnessScriptHash(scriptHash)
	case transaction.P2TR:
		if len(script) != 3 {
			return "", ierrors.ErrInvalidScript
		}

		witnessProg, err := hex.DecodeString(script[2])
		if err != nil {
			return "", err
		}

		return NewPayToTaproot(witnessProg)
	case transaction.OP_RETURN_TYPE:
		return "", nil

	case transaction.P2MS:
		return "", nil

	default:
		return "", errors.New("invalid script type")
	}
}

func NewPayToPubKey(pubkey []byte, compressed bool) (string, error) {
	return hex.EncodeToString(pubkey), nil
}

func NewPayToPubKeyHash(pubkeyHash []byte) (string, error) {
	if len(pubkeyHash) != ripemd160.Size {
		return "", errors.New("pkHash must be 20 bytes")
	}
	return base58.CheckEncode(pubkeyHash[:ripemd160.Size], 0x00), nil
}

func NewPayToScriptHashFromScriptHash(scriptHash []byte) (string, error) {
	if len(scriptHash) != ripemd160.Size {
		return "", errors.New("scriptHash must be 20 bytes")
	}
	return base58.CheckEncode(scriptHash[:ripemd160.Size], 0x05), nil
}

func NewPayToWitnessPubKeyHash(witnessProg []byte) (string, error) {
	if len(witnessProg) != 20 {
		return "", errors.New("witness program must be 20 " +
			"bytes for p2wpkh")
	}
	return encodeSegWitAddress("bc", 0x00, witnessProg)
}

func NewPayToWitnessScriptHash(witnessProg []byte) (string, error) {
	if len(witnessProg) != 32 {
		return "", errors.New("witness program must be 32 " +
			"bytes for p2wsh")
	}
	return encodeSegWitAddress("bc", 0x00, witnessProg)
}

func NewPayToTaproot(tapscript []byte) (string, error) {
	if len(tapscript) != 32 {
		return "", errors.New("witness program must be 32 bytes for " +
			"p2tr")
	}
	return encodeSegWitAddress("bc", 0x01, tapscript)
}

// TODO
func NewPayToScriptHashFromScript(script []byte) (string, error) {
	return "", nil
}

func CheckDecode(input string) (result []byte, version byte, err error) {
	decoded := base58.Decode(input)
	if len(decoded) < 5 {
		return nil, 0, ierrors.ErrInvalidAddress
	}
	version = decoded[0]
	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])
	if checksum(decoded[:len(decoded)-4]) != cksum {
		return nil, 0, base58.ErrChecksum
	}
	payload := decoded[1 : len(decoded)-4]
	result = append(result, payload...)
	return
}

func checksum(input []byte) (cksum [4]byte) {
	h := sha256.Sum256(input)
	h2 := sha256.Sum256(h[:])
	copy(cksum[:], h2[:4])
	return
}

func decodeSegWitAddress(address string) (byte, []byte, error) {
	_, data, bech32version, err := bech32.DecodeGeneric(address)
	if err != nil {
		return 0, nil, err
	}

	if len(data) < 1 {
		return 0, nil, fmt.Errorf("no witness version")
	}

	version := data[0]
	if version > 16 {
		return 0, nil, fmt.Errorf("invalid witness version: %v", version)
	}

	regrouped, err := bech32.ConvertBits(data[1:], 5, 8, false)
	if err != nil {
		return 0, nil, err
	}

	if len(regrouped) < 2 || len(regrouped) > 40 {
		return 0, nil, fmt.Errorf("invalid data length")
	}

	if version == 0 && len(regrouped) != 20 && len(regrouped) != 32 {
		return 0, nil, fmt.Errorf("invalid data length for witness "+
			"version 0: %v", len(regrouped))
	}

	if version == 0 && bech32version != bech32.Version0 {
		return 0, nil, fmt.Errorf("invalid checksum expected bech32 " +
			"encoding for address with witness version 0")
	}

	if version == 1 && bech32version != bech32.VersionM {
		return 0, nil, fmt.Errorf("invalid checksum expected bech32m " +
			"encoding for address with witness version 1")
	}

	return version, regrouped, nil
}

func encodeSegWitAddress(hrp string, witnessVersion byte, witnessProgram []byte) (string, error) {
	converted, err := bech32.ConvertBits(witnessProgram, 8, 5, true)
	if err != nil {
		return "", err
	}

	combined := make([]byte, len(converted)+1)
	combined[0] = witnessVersion
	copy(combined[1:], converted)

	var bech string
	switch witnessVersion {
	case 0:
		bech, err = bech32.Encode(hrp, combined)

	case 1:
		bech, err = bech32.EncodeM(hrp, combined)

	default:
		return "", fmt.Errorf("unsupported witness version %d",
			witnessVersion)
	}
	if err != nil {
		return "", err
	}

	version, program, err := decodeSegWitAddress(bech)
	if err != nil {
		return "", fmt.Errorf("invalid segwit address: %v", err)
	}

	if version != witnessVersion || !bytes.Equal(program, witnessProgram) {
		return "", fmt.Errorf("invalid segwit address")
	}

	return bech, nil
}
