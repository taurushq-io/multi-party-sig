package arith

import "encoding/binary"

const IDByteSize = 4

// IDToBytes returns a 4 byte big-endian representation of id
func IDToBytes(id uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, id)
	return b
}

// IDFromBytes returns a unit32 from the first 4 bytes of b.
func IDFromBytes(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}
