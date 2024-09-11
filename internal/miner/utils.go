package miner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// calculates the Merkle root from a list of transaction IDs.
func GenerateMerkleRoot(txids []string) (string, error) {
	if len(txids) == 0 {
		return "", errors.New("empty transaction list")
	}

	for len(txids) > 1 {
		nextTxids := make([]string, (len(txids)+1)/2)
		for i := 0; i < len(txids); i += 2 {
			var pairHash string
			if i+1 == len(txids) {
				pairHash = Hash256(txids[i] + txids[i])
			} else {
				pairHash = Hash256(txids[i] + txids[i+1])
			}
			nextTxids[i/2] = pairHash
		}
		txids = nextTxids
	}

	return txids[0], nil
}

// reverses the order of bytes in a byte slice.
// This is useful for converting between big-endian and little-endian representations.
func reverse(b []byte) []byte {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// decodes a hexadecimal string to bytes.
// It returns an error if the input is not valid hexadecimal.
func HexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// performs a double SHA256 hash on the input string and returns the result as a hexadecimal string.
// This is the standard hashing method used in various parts of the Bitcoin protocol.
func Hash256(input string) string {
	decoded, err := HexDecode(input)
	if err != nil {
		return "" // Return empty string on invalid input
	}

	hasher := sha256.New()
	hasher.Write(decoded)
	firstHash := hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(firstHash)
	secondHash := hasher.Sum(nil)

	return hex.EncodeToString(secondHash)
}
