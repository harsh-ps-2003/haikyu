package miner

import (
	"crypto/sha256"
	"encoding/hex"
)

func GenerateMerkleRoot(txids []string) string {
	if len(txids) == 0 {
		return ""
	}

	for len(txids) > 1 {
		var nextTxids []string

		for i := 0; i < len(txids); i += 2 {
			var pairHash string

			if i+1 == len(txids) {
				pairHash = Hash256(txids[i] + txids[i])
			} else {
				pairHash = Hash256(txids[i] + txids[i+1])
			}

			nextTxids = append(nextTxids, pairHash)
		}

		txids = nextTxids
	}

	return txids[0]
}

func reverse(b []byte) []byte {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func HexMustDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func Hash256(input string) string {
	// First hash
	hasher := sha256.New()
	hasher.Write(HexMustDecode(input))
	firstHash := hasher.Sum(nil)

	// Second hash
	hasher.Reset()
	hasher.Write(firstHash)
	secondHash := hasher.Sum(nil)

	// Convert the final hash to a hexadecimal string
	return hex.EncodeToString(secondHash)
}
