package hash

import (
	"encoding/binary"
	"errors"
	"math/big"
	"sort"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
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
	out := make([]byte, params.BytesScalar)
	_, err := hash.h.Read(out)
	if err != nil {
		return nil, err
	}
	return scalar.SetBytes(out), nil
}

// ReadFqNegative generates a big.Int in the interval ±q, by reading from hash.Hash.
func (hash *Hash) ReadFqNegative() (*big.Int, error) {
	var n big.Int
	out := make([]byte, params.BytesScalar+1)
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
func (hash *Hash) ReadBytes(in []byte) ([]byte, error) {
	if len(in) < params.HashBytes {
		panic("hash: tried to read less than 256 bits")
	}
	_, err := hash.h.Read(in)
	if err != nil {
		return nil, err
	}
	return in, nil
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
		d, _ := i.GobEncode()
		if _, err = hash.h.Write(d); err != nil {
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

// WriteAny takes many different data types and writes them to the hash state.
func (hash *Hash) WriteAny(data ...interface{}) error {
	var err error

	bufPaillier := make([]byte, params.BytesPaillier)
	bufCipherText := make([]byte, params.BytesCiphertext)
	bufScalar := make([]byte, params.BytesScalar)

	for _, d := range data {
		switch t := d.(type) {
		case []byte:
			_, err = hash.h.Write(t)
		case *curve.Point:
			if t == nil {
				return errNilValue
			}
			_, err = hash.h.Write(t.BytesCompressed())
		case *curve.Scalar:
			if t == nil {
				return errNilValue
			}
			_, err = hash.h.Write(t.BigInt().FillBytes(bufScalar))
		case map[uint32]*curve.Point:
			keys := make(sort.IntSlice, 0, len(t))
			for k := range t {
				keys = append(keys, int(k))
			}
			keys.Sort()

			for _, k := range keys {
				if _, err = hash.h.Write(t[uint32(k)].BytesCompressed()); err != nil {
					return err
				}
			}
		case []*curve.Point:
			// TODO maybe write the length?
			for _, p := range t {
				if _, err = hash.h.Write(p.BytesCompressed()); err != nil {
					return err
				}
			}
		case *big.Int:
			if t == nil {
				return errNilValue
			}
			b, _ := t.GobEncode()
			_, err = hash.h.Write(b)
		case *paillier.Ciphertext:
			if t == nil {
				return errNilValue
			}
			_, err = hash.h.Write(t.Int().FillBytes(bufCipherText))
		case *paillier.PublicKey:
			if t == nil {
				return errNilValue
			}
			_, err = hash.h.Write(t.N.FillBytes(bufPaillier))
		case *pedersen.Parameters:
			if t == nil {
				return errNilValue
			}
			if _, err = hash.h.Write(t.N.FillBytes(bufPaillier)); err != nil {
				return err
			}
			if _, err = hash.h.Write(t.S.FillBytes(bufPaillier)); err != nil {
				return err
			}
			_, err = hash.h.Write(t.T.FillBytes(bufPaillier))
		default:
			err = errors.New("hash: unsupported type")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteBytes writes data to the hash state.
func (hash *Hash) WriteBytes(data ...[]byte) error {
	var err error
	for _, d := range data {
		if _, err = hash.h.Write(d); err != nil {
			return err
		}
	}
	return nil
}

// Clone returns a copy of the Hash in its current state.
func (hash *Hash) Clone() *Hash {
	return &Hash{h: hash.h.Clone()}
}

// CloneWithID returns a copy of the Hash in its current state, but also writes the ID to the new state.
func (hash *Hash) CloneWithID(id string) *Hash {
	h2 := hash.h.Clone()
	_, _ = h2.Write([]byte(id))
	return &Hash{h: h2}
}
