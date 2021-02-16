package secp256k1

import (
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var q = secp256k1.S256().N

type Scalar struct {
	s big.Int
}

// NewScalar returns a new zero Scalar.
func NewScalar() *Scalar {
	return &Scalar{}
}

// MultiplyAdd sets s = x * y + z mod l, and returns s.
func (s *Scalar) MultiplyAdd(x, y, z *Scalar) *Scalar {
	s.s.Mul(&x.s, &y.s)
	s.s.Add(&s.s, &z.s)
	s.s.Mod(&s.s, q)
	return s
}

// Add sets s = x + y mod l, and returns s.
func (s *Scalar) Add(x, y *Scalar) *Scalar {
	s.s.Add(&x.s, &y.s)
	s.s.Mod(&s.s, q)
	return s
}

// Subtract sets s = x - y mod l, and returns s.
func (s *Scalar) Subtract(x, y *Scalar) *Scalar {
	s.s.Sub(&x.s, &y.s)
	s.s.Mod(&s.s, q)
	return s
}

// Negate sets s = -x mod l, and returns s.
func (s *Scalar) Negate(x *Scalar) *Scalar {
	s.s.Neg(&x.s)
	s.s.Mod(&s.s, q)
	return s
}

// Multiply sets s = x * y mod l, and returns s.
func (s *Scalar) Multiply(x, y *Scalar) *Scalar {
	s.s.Mul(&x.s, &y.s)
	s.s.Mod(&s.s, q)
	return s
}

// Set sets s = x, and returns s.
func (s *Scalar) Set(x *Scalar) *Scalar {
	s.s.Set(&x.s)
	return s
}

// Bytes returns the canonical 32 bytes little-endian encoding of s.
func (s *Scalar) Bytes() []byte {
	return s.Bytes()
}

// Equal returns 1 if s and t are equal, and 0 otherwise.
func (s *Scalar) Equal(t *Scalar) int {
	if s.s.Cmp(&t.s) == 1 {
		return 1
	}
	return 0
}

// Invert sets s to the inverse of a nonzero scalar v, and returns s.
//
// If t is zero, Invert will panic.
func (s *Scalar) Invert(t *Scalar) *Scalar {
	s.s.ModInverse(&t.s, q)
	return s
}
