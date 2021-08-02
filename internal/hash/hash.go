package hash

import (
	"fmt"
	"io"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/internal/params"
	"github.com/zeebo/blake3"
)

const DigestLengthBytes = params.SecBytes * 2 // 64

// Hash is the hash function we use for generating commitments, consuming CMP types, etc.
//
// Internally, this is a wrapper around sha3.ShakeHash, but any hash function with
// an easily extendable output would work as well.
type Hash struct {
	h *blake3.Hasher
}

// New creates a Hash struct where the internal hash function is initialized with "CMP".
func New() *Hash {
	hash := &Hash{h: blake3.New()}
	return hash
}

// Digest returns a reader for the current output of the function.
//
// This finalizes the current state of the hash, and returns what's
// essentially a stream of random bytes.
func (hash *Hash) Digest() io.Reader {
	return hash.h.Digest()
}

// Sum returns a slice of length DigestLengthBytes resulting from the current hash state.
// If a different length is required, use io.ReadFull(hash.Digest(), out) instead.
func (hash *Hash) Sum() []byte {
	out := make([]byte, DigestLengthBytes)
	if _, err := io.ReadFull(hash.Digest(), out); err != nil {
		panic(fmt.Sprintf("hash.ReadBytes: internal hash failure: %v", err))
	}
	return out
}

// WriteAny takes many different data types and writes them to the hash state.
//
// Currently supported types:
//
//  - []byte
//  - *big.Int
//  - hash.WriterToWithDomain
//
// This function will apply its own domain separation for the first two types.
// The last type already suggests which domain to use, and this function respects it.
func (hash *Hash) WriteAny(data ...interface{}) error {
	var err error
	for _, d := range data {
		switch t := d.(type) {
		case []byte:
			err = writeWithDomain(hash.h, &BytesWithDomain{
				TheDomain: "[]byte",
				Bytes:     t,
			})
			if err != nil {
				return fmt.Errorf("hash.Hash: write []byte: %w", err)
			}
		case *big.Int:
			if t == nil {
				return fmt.Errorf("hash.Hash: write *big.Int: nil")
			}
			bytes := make([]byte, params.BytesIntModN)
			if t.BitLen() <= params.BitsIntModN && t.Sign() == 1 {
				t.FillBytes(bytes)
			} else {
				bytes, err = t.GobEncode()
				if err != nil {
					return fmt.Errorf("hash.Hash: GobEncode: %w", err)
				}
			}
			err = writeWithDomain(hash.h, &BytesWithDomain{
				TheDomain: "big.Int",
				Bytes:     bytes,
			})
			if err != nil {
				return fmt.Errorf("hash.Hash: write *big.Int: %w", err)
			}
		case WriterToWithDomain:
			if err = writeWithDomain(hash.h, t); err != nil {
				return fmt.Errorf("hash.Hash: write io.WriterTo: %w", err)
			}
		default:
			panic("hash.Hash: unsupported type")
		}
	}
	return nil
}

// Clone returns a copy of the Hash in its current state.
func (hash *Hash) Clone() *Hash {
	return &Hash{h: hash.h.Clone()}
}
