package hash

import (
	"encoding/binary"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"golang.org/x/crypto/sha3"
)

// Hash is a wrapper for sha3.ShakeHash which extends its functionality to work with CMP's data types.
type Hash struct {
	h sha3.ShakeHash
}

const hashRate = 136

// Sum hashes the given components and returns a digest of the default size (usually 64 byte)
func (hash *Hash) Sum(components ...[]byte) ([]byte, error) {
	return hash.hashToBytes(params.HashBytes, components...)
}

func (hash *Hash) hashToBytes(size int, components ...[]byte) ([]byte, error) {
	var err error
	sizeBuffer := make([]byte, 8)

	h := hash.h.Clone()
	for _, c := range components {
		binary.BigEndian.PutUint64(sizeBuffer, uint64(len(c)))
		_, err = h.Write(sizeBuffer)
		if err != nil {
			return nil, err
		}

		_, err = h.Write(c)
		if err != nil {
			return nil, err
		}
	}
	out := make([]byte, size)
	_, err = h.Read(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReadScalar generates a curve.Scalar by reading from hash.Hash.
// To prevent statistical bias, we sample double the size.
func (hash *Hash) ReadScalar() (*curve.Scalar, error) {
	var scalar curve.Scalar
	out, err := hash.hashToBytes(curve.ByteSize * 2)
	if err != nil {
		return nil, err
	}
	scalar.SetBytes(out)
	return &scalar, nil
}

// ReadIntInInterval generates a big.Int in the interval ±2ᵖᵒʷᵉʳ, by reading from hash.Hash.
func (hash *Hash) ReadIntInInterval(power int) (*big.Int, error) {
	var n big.Int
	lenBytes := (power+7)/8 + 1
	out := make([]byte, lenBytes)
	_, err := hash.h.Read(out)
	if err != nil {
		return nil, err
	}

	// use the first byte to determine if the result should be negative
	isNeg := (out[0] & 1) == 1
	out = out[1:]

	n.SetBytes(out)
	if isNeg {
		n.Neg(&n)
	}

	return &n, nil
}

// ReadIntModN generates a positive big.Int in the interval [0,n[, by reading from hash.Hash.
// To prevent statistical bias, we sample double the size.
func (hash *Hash) ReadIntModN(n *big.Int) (*big.Int, error) {
	var r big.Int
	lenBytes := (n.BitLen() + 7) / 8
	out := make([]byte, 2*lenBytes)
	_, err := hash.h.Read(out)
	if err != nil {
		return nil, err
	}

	r.SetBytes(out)
	r.Mod(&r, n)

	return &r, nil
}

// ReadBytes returns numBytes by reading from hash.Hash.
func (hash *Hash) ReadBytes(numBytes int) ([]byte, error) {
	out := make([]byte, numBytes)
	_, err := hash.h.Read(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReadBools generates numBools by reading from hash.Hash.
func (hash *Hash) ReadBools(numBools int) ([]bool, error) {
	numBytes := (numBools + 7) / 8
	tmpBytes := make([]byte, numBytes)

	if _, err := hash.h.Read(tmpBytes); err != nil {
		return nil, err
	}

	out := make([]bool, numBools)
	bit := 0
	for i := 0; i < numBools; i++ {
		idx := i / 8
		b := tmpBytes[idx]
		out[i] = (b>>bit)&1 == 1
		bit = (bit + 1) % 8
	}

	return out, nil
}

// WriteInt writes a variable number of big.Int to the hash state.
func (hash *Hash) WriteInt(ints ...*big.Int) error {
	var err error
	for _, i := range ints {
		// append sign
		sign := []byte{byte(i.Sign())}
		if _, err = hash.h.Write(sign); err != nil {
			return err
		}

		// append actual bytes
		_, err = hash.h.Write(i.Bytes())
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteInt writes data to the hash state.
// Implements io.Writer
func (hash *Hash) Write(data []byte) (int, error) {
	return hash.h.Write(data)
}

// WritePoint takes an arbitrary number of points and hashes them to the hash state.
func (hash *Hash) WritePoint(pts ...*curve.Point) error {
	var err error
	for _, p := range pts {
		_, err = hash.h.Write(p.BytesCompressed())
		if err != nil {
			return err
		}
	}
	return nil
}

// Clone returns a copy of the Hash in its current state.
func (hash *Hash) Clone() *Hash {
	return &Hash{h: hash.h.Clone()}
}

// Clone returns a copy of the Hash in its current state, but also writes the ID to the new state.
func (hash *Hash) CloneWithID(id uint32) *Hash {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, id)
	h2 := hash.h.Clone()
	_, _ = h2.Write(b)
	return &Hash{h: h2}
}

// New creates a Hash struct with initial data.
func New(init []byte) *Hash {
	hash := &Hash{sha3.NewShake256()}

	N := []byte("CMP")
	initBlock := make([]byte, 0, 9*2+len(N)+len(init))
	initBlock = append(initBlock, leftEncode(uint64(len(N)*8))...)
	initBlock = append(initBlock, N...)
	initBlock = append(initBlock, leftEncode(uint64(len(init)*8))...)
	initBlock = append(initBlock, init...)

	_, _ = hash.h.Write(bytepad(initBlock, hashRate))

	return hash
}

func bytepad(input []byte, w int) []byte {
	// leftEncode always returns max 9 bytes
	buf := make([]byte, 0, 9+len(input)+w)
	buf = append(buf, leftEncode(uint64(w))...)
	buf = append(buf, input...)
	padlen := w - (len(buf) % w)
	return append(buf, make([]byte, padlen)...)
}

func leftEncode(value uint64) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[1:], value)
	// Trim all but last leading zero bytes
	i := byte(1)
	for i < 8 && b[i] == 0 {
		i++
	}
	// Prepend number of encoded bytes
	b[i-1] = 9 - i
	return b[i-1:]
}
