package ot

// bitAt returns the ith bit in a vector of bits.
//
// The indexing goes from bytes 0..len() - 1, and from the LSB to the MSB inside
// of each byte.
func bitAt(i int, data []byte) byte {
	return (data[i>>3] >> (i & 0b111)) & 1
}
