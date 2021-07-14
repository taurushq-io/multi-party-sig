package hash

import (
	"fmt"
	"io"
	"math/big"

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

// Read makes Hash implement the io.Reader interface.
//
// Implementing this interface is convenient in ZK proofs, which need to use the
// output of a hash function as randomness later on.
func (hash *Hash) Read(buf []byte) (n int, err error) {
	return hash.h.Read(buf)
}

// ReadFqNegative generates a big.Int in the interval ±q, by reading from hash.Hash.
func (hash *Hash) ReadFqNegative() *big.Int {
	var n big.Int
	out := make([]byte, params.BytesScalar+1)
	_, _ = hash.h.Read(out)

	// use the first byte to determine if the result should be negative
	isNeg := (out[0] & 1) == 1
	out = out[1:]

	n.SetBytes(out)
	if isNeg {
		n.Neg(&n)
	}

	return &n
}

// ReadBytes returns numBytes by reading from hash.Hash.
// if in is nil, ReadBytes returns the minimum safe length
func (hash *Hash) ReadBytes(in []byte) ([]byte, error) {
	if in == nil {
		in = make([]byte, params.HashBytes)
	}
	if len(in) < params.HashBytes {
		panic("hash.ReadBytes: tried to read less than 256 bits")
	}
	_, err := hash.h.Read(in)
	if err != nil {
		return nil, err
	}
	return in, err
}

// Write writes data to the hash state.
// Implements io.Writer
func (hash *Hash) Write(data []byte) (int, error) {
	// the underlying hash function never returns an error
	return hash.h.Write(data)
}

// WriteAny takes many different data types and writes them to the hash state.
func (hash *Hash) WriteAny(data ...interface{}) (int64, error) {
	n := int64(0)
	for _, d := range data {
		switch t := d.(type) {
		case []byte:
			n0, _ := hash.h.Write(t)
			n += int64(n0)
		case []*curve.Point:
			for _, p := range t {
				n0, err := p.WriteTo(hash.h)
				n += n0
				if err != nil {
					return n, fmt.Errorf("hash.Hash: write []*curve.Point: %w", err)
				}
			}
		case []curve.Point:
			for _, p := range t {
				n0, err := p.WriteTo(hash.h)
				n += n0
				if err != nil {
					return n, fmt.Errorf("hash.Hash: write []curve.Point: %w", err)
				}
			}
		case *big.Int:
			if t == nil {
				return n, fmt.Errorf("hash.Hash: write *big.Int: nil")
			}
			b := make([]byte, params.BytesIntModN)
			if t.BitLen() <= params.BitsIntModN && t.Sign() == 1 {
				t.FillBytes(b)
			} else {
				b, _ = t.GobEncode()
			}
			n0, _ := hash.h.Write(b)
			n += int64(n0)
		case io.WriterTo:
			n0, err := t.WriteTo(hash.h)
			n += n0
			if err != nil {
				return n, fmt.Errorf("hash.Hash: write io.WriterTo: %w", err)
			}
		default:
			panic("hash.Hash: unsupported type")
			//return n, errors.New("hash.Hash: unsupported type")
		}
	}
	return n, nil
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
