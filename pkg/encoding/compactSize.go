package encoding

import (
	"encoding/binary"
	"math"
)

func CompactSize(val uint64) []byte {
	var buf []byte

	switch {
	case val < 0xfd:
		buf = []byte{uint8(val)}

	case val <= math.MaxUint16:
		buf = make([]byte, 3)
		buf[0] = 0xfd
		binary.LittleEndian.PutUint16(buf[1:], uint16(val))

	case val <= math.MaxUint32:
		buf = make([]byte, 5)
		buf[0] = 0xfe
		binary.LittleEndian.PutUint32(buf[1:], uint32(val))

	default:
		buf = make([]byte, 9)
		buf[0] = 0xff
		binary.LittleEndian.PutUint64(buf[1:], val)
	}

	return buf
}
