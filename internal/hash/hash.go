package hash

import (
	"fmt"
	"io"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/internal/params"
	"github.com/taurusgroup/cmp-ecdsa/internal/writer"
	"github.com/zeebo/blake3"
)

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

// DefaultDigest tries to read the default digest length of this hash into a buffer.
//
// The buffer can be nil, in which case this function will allocate a buffer of
// the right length. If the buffer is too short to contain a safe hash length,
// this function will panic. Otherwise, it will fill the first bytes of the buffer.
func (hash *Hash) DefaultDigest(out []byte) []byte {
	if out == nil {
		out = make([]byte, params.HashBytes)
	}
	if len(out) < params.HashBytes {
		panic(fmt.Sprintf("hash.ReadBytes: tried to read less than %d bits", 8*params.HashBytes))
	}
	if _, err := io.ReadFull(hash.Digest(), out[:params.HashBytes]); err != nil {
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
//  - writer.WriterToWithDomain
//
// This function will apply its own domain separation for the first two types.
// The last type already suggests which domain to use, and this function respects it.
func (hash *Hash) WriteAny(data ...interface{}) (int64, error) {
	total := int64(0)
	for _, d := range data {
		switch t := d.(type) {
		case []byte:
			n, err := writer.WriteWithDomain(hash.h, &writer.BytesWithDomain{
				TheDomain: "[]byte",
				Bytes:     t,
			})
			total += n
			if err != nil {
				return total, fmt.Errorf("hash.Hash: write []byte: %w", err)
			}
		case *big.Int:
			if t == nil {
				return total, fmt.Errorf("hash.Hash: write *big.Int: nil")
			}
			bytes := make([]byte, params.BytesIntModN)
			if t.BitLen() <= params.BitsIntModN && t.Sign() == 1 {
				t.FillBytes(bytes)
			} else {
				var err error
				bytes, err = t.GobEncode()
				if err != nil {
					return total, fmt.Errorf("hash.Hash: GobEncode: %w", err)
				}
			}
			n, err := writer.WriteWithDomain(hash.h, &writer.BytesWithDomain{
				TheDomain: "big.Int",
				Bytes:     bytes,
			})
			total += n
			if err != nil {
				return total, fmt.Errorf("hash.Hash: write *big.Int: %w", err)
			}
		case writer.WriterToWithDomain:
			n, err := writer.WriteWithDomain(hash.h, t)
			total += n
			if err != nil {
				return total, fmt.Errorf("hash.Hash: write io.WriterTo: %w", err)
			}
		default:
			panic("hash.Hash: unsupported type")
		}
	}
	return total, nil
}

// Clone returns a copy of the Hash in its current state.
func (hash *Hash) Clone() *Hash {
	return &Hash{h: hash.h.Clone()}
}
