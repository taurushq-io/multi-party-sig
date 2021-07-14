package hash

import (
	"fmt"
	"io"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"golang.org/x/crypto/sha3"
)

// Hash is the hash function we use for generating commitments, consuming CMP types, etc.
//
// Internally, this is a wrapper around sha3.ShakeHash, but any hash function with
// an easily extendable output would work as well.
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

// ReadBytes fills a buffer with bytes.
//
// If in is nil, then the default number of bytes are read into a new buffer.
//
// Otherwise, in is filled with exactly the right number of bytes.
//
// This function will panic if in is smaller than a safe number of bytes.
func (hash *Hash) ReadBytes(in []byte) []byte {
	if in == nil {
		in = make([]byte, params.HashBytes)
	}
	if len(in) < params.HashBytes {
		panic(fmt.Sprintf("hash.ReadBytes: tried to read less than %d bits", 8*params.HashBytes))
	}
	if _, err := hash.Read(in); err != nil {
		panic(fmt.Sprintf("hash.ReadBytes: internal hash failure: %v", err))
	}
	return in
}

// Write writes data to the hash state.
//
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
			n0, err := hash.Write(t)
			if err != nil {
				return n, fmt.Errorf("hash.Hash: write []byte: %w", err)
			}
			n += int64(n0)
		case *big.Int:
			if t == nil {
				return n, fmt.Errorf("hash.Hash: write *big.Int: nil")
			}
			b := make([]byte, params.BytesIntModN)
			if t.BitLen() <= params.BitsIntModN && t.Sign() == 1 {
				t.FillBytes(b)
			} else {
				var err error
				b, err = t.GobEncode()
				if err != nil {
					return n, fmt.Errorf("hash.Hash: GobEncode: %w", err)
				}
			}
			n0, err := hash.Write(b)
			if err != nil {
				return n, fmt.Errorf("hash.Hash: write *big.Int: %w", err)
			}
			n += int64(n0)
		case io.WriterTo:
			n0, err := t.WriteTo(hash)
			n += n0
			if err != nil {
				return n, fmt.Errorf("hash.Hash: write io.WriterTo: %w", err)
			}
		default:
			panic("hash.Hash: unsupported type")
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
	cloned := hash.Clone()
	_, _ = cloned.Write([]byte(id))
	return cloned
}
