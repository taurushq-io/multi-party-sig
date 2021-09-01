package ot

func bitAt(i int, data []byte) byte {
	return (data[i>>3] >> (i & 0b111)) & 1
}
