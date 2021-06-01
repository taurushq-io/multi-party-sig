package hash

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"golang.org/x/crypto/sha3"
)

// Hash is a wrapper for sha3.ShakeHash which extends its functionality to work with CMP's data types.
type Hash struct {
	h sha3.ShakeHash
}

// New creates a Hash struct with initial data.
func New() *Hash {
	hash := &Hash{sha3.NewCShake128(nil, []byte("CMP"))}
	return hash
}

var errNilValue = errors.New("provided element was null")

// ReadScalar generates a curve.Scalar by reading from hash.Hash.
// To prevent statistical bias, we sample double the size.
func (hash *Hash) ReadScalar() (*curve.Scalar, error) {
	var scalar curve.Scalar
	out := make([]byte, params.BytesScalar)
	_, err := hash.h.Read(out)
	if err != nil {
		return nil, fmt.Errorf("hash.ReadScalar: %w", err)
	}
	return scalar.SetBytes(out), nil
}

// ReadFqNegative generates a big.Int in the interval ±q, by reading from hash.Hash.
func (hash *Hash) ReadFqNegative() (*big.Int, error) {
	var n big.Int
	out := make([]byte, params.BytesScalar+1)
	_, err := hash.h.Read(out)
	if err != nil {
		return nil, fmt.Errorf("hash.ReadFqNegative: %w", err)
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

// ReadIntsModN generates a positive big.Int in the interval [0,n[, by reading from hash.Hash.
// TODO How much bigger should the buffer be in order to minimize statistical bias?
func (hash *Hash) ReadIntsModN(n *big.Int, num int) ([]*big.Int, error) {
	intBuffer := make([]byte, params.BytesPaillier)
	out := make([]*big.Int, num)
	for i := range out {
		var r big.Int
		if _, err := hash.h.Read(intBuffer); err != nil {
			return nil, fmt.Errorf("hash.ReadIntsModN: %w", err)
		}
		r.SetBytes(intBuffer)
		r.Mod(&r, n)
		out[i] = &r
	}

	return out, nil
}

// ReadBytes returns numBytes by reading from hash.Hash.
func (hash *Hash) ReadBytes(in []byte) ([]byte, error) {
	if len(in) < params.HashBytes {
		panic("hash.ReadBytes: tried to read less than 256 bits")
	}
	_, err := hash.h.Read(in)
	if err != nil {
		return nil, fmt.Errorf("hash.ReadBytes: %w", err)
	}
	return in, nil
}

// ReadBools generates numBools by reading from hash.Hash.
func (hash *Hash) ReadBools(numBools int) ([]bool, error) {
	numBytes := (numBools + 7) / 8
	tmpBytes := make([]byte, numBytes)

	if _, err := hash.h.Read(tmpBytes); err != nil {
		return nil, fmt.Errorf("hash.ReadBools: %w", err)
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
		d, _ := i.GobEncode()
		if _, err = hash.h.Write(d); err != nil {
			return fmt.Errorf("hash.WriteInt: %w", err)
		}
	}
	return nil
}

// Write writes data to the hash state.
// Implements io.Writer
func (hash *Hash) Write(data []byte) (int, error) {
	n, err := hash.h.Write(data)
	if err != nil {
		return n, fmt.Errorf("hash.Write: %w", err)
	}
	return n, nil
}

// WriteAny takes many different data types and writes them to the hash state.
func (hash *Hash) WriteAny(data ...interface{}) error {
	var err error

	for _, d := range data {
		switch t := d.(type) {
		case []byte:
			_, err = hash.h.Write(t)
			if err != nil {
				return fmt.Errorf("hash.Hash: write []byte: %w", err)
			}
		case map[uint32]*curve.Point:
			keys := make(sort.IntSlice, 0, len(t))
			for k := range t {
				keys = append(keys, int(k))
			}
			keys.Sort()

			for _, k := range keys {
				if _, err = t[uint32(k)].WriteTo(hash.h); err != nil {
					return fmt.Errorf("hash.Hash: write map[uint32]*curve.Point: %w", err)
				}
			}
		case []*curve.Point:
			// TODO maybe write the length?
			for _, p := range t {
				if _, err = p.WriteTo(hash.h); err != nil {
					return fmt.Errorf("hash.Hash: write []*curve.Point: %w", err)
				}
			}
		case *big.Int:
			if t == nil {
				return fmt.Errorf("hash.Hash: write *big.Int: %w", errNilValue)
			}
			b, _ := t.GobEncode()
			_, err = hash.h.Write(b)
			if err != nil {
				return fmt.Errorf("hash.Hash: write *big.Int: %w", err)
			}
		case io.WriterTo:
			_, err = t.WriteTo(hash.h)
			if err != nil {
				return fmt.Errorf("hash.Hash: write io.WriterTo: %w", err)
			}
		default:
			return errors.New("hash.Hash: unsupported type")
		}
	}
	return nil
}

// WriteBytes writes data to the hash state.
func (hash *Hash) WriteBytes(data ...[]byte) error {
	var err error
	for _, d := range data {
		if _, err = hash.h.Write(d); err != nil {
			return fmt.Errorf("hash.WriteBytes: %w", err)
		}
	}
	return nil
}

// Clone returns a copy of the Hash in its current state.
func (hash *Hash) Clone() *Hash {
	return &Hash{h: hash.h.Clone()}
}

// CloneWithID returns a copy of the Hash in its current state, but also writes the ID to the new state.
func (hash *Hash) CloneWithID(id party.ID) *Hash {
	h2 := hash.h.Clone()
	_, _ = h2.Write([]byte(id))
	return &Hash{h: h2}
}
