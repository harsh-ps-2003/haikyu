package encoding

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

type LittleEndianBuffer struct {
	buffer bytes.Buffer
}

func NewLEBuffer() *LittleEndianBuffer {
	return &LittleEndianBuffer{}
}

func (b *LittleEndianBuffer) Set(value any) {
	binary.Write(&b.buffer, binary.LittleEndian, value)
}

func (b *LittleEndianBuffer) SetBytes(data []byte, convertBEToLE bool) {
	if convertBEToLE {
		for i := 0; i < len(data)/2; i++ {
			data[i], data[len(data)-i-1] = data[len(data)-i-1], data[i]
		}
	}
	b.buffer.Write(data)
}

func (b *LittleEndianBuffer) GetBuffer() []byte {
	return b.buffer.Bytes()
}

func (b *LittleEndianBuffer) DoubleHash() []byte {
	h := sha256.New()
	h.Write(b.buffer.Bytes())
	firstHash := h.Sum(nil)

	h.Reset()
	h.Write(firstHash)
	return h.Sum(nil)
}
