package curve

import (
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

type Scalar struct {
	s big.Int
}

// NewScalar returns a new zero Scalar.
func NewScalar() *Scalar {
	return &Scalar{}
}

// NewScalarBigInt returns a new Scalar from a big.Int
func NewScalarBigInt(n *big.Int) *Scalar {
	var s Scalar
	return s.SetBigInt(n)
}

// NewScalarUInt returns a Scalar from the uint32 n
func NewScalarUInt(n uint32) *Scalar {
	var s Scalar
	s.s.SetInt64(int64(n))
	return &s
}

// MultiplyAdd sets s = x * y + z mod l, and returns s.
func (s *Scalar) MultiplyAdd(x, y, z *Scalar) *Scalar {
	s.s.Mul(&x.s, &y.s)
	s.s.Add(&s.s, &z.s)
	s.s.Mod(&s.s, Q)
	return s
}

// Add sets s = x + y mod l, and returns s.
func (s *Scalar) Add(x, y *Scalar) *Scalar {
	s.s.Add(&x.s, &y.s)
	s.s.Mod(&s.s, Q)
	return s
}

// Subtract sets s = x - y mod l, and returns s.
func (s *Scalar) Subtract(x, y *Scalar) *Scalar {
	s.s.Sub(&x.s, &y.s)
	s.s.Mod(&s.s, Q)
	return s
}

// Negate sets s = -x mod l, and returns s.
func (s *Scalar) Negate(x *Scalar) *Scalar {
	s.s.Neg(&x.s)
	s.s.Mod(&s.s, Q)
	return s
}

// Multiply sets s = x * y mod l, and returns s.
func (s *Scalar) Multiply(x, y *Scalar) *Scalar {
	s.s.Mul(&x.s, &y.s)
	s.s.Mod(&s.s, Q)
	return s
}

// Set sets s = x, and returns s.
func (s *Scalar) Set(x *Scalar) *Scalar {
	s.s.Set(&x.s)
	return s
}

// SetInt64 sets s = x, and returns s.
func (s *Scalar) SetInt64(i int64) *Scalar {
	s.s.SetInt64(i)
	return s
}

// SetBigInt sets s = x, and returns s.
func (s *Scalar) SetBigInt(i *big.Int) *Scalar {
	s.s.Set(i)
	s.s.Mod(&s.s, Q)
	return s
}

// SetBigInt sets s = x, and returns s.
func (s *Scalar) SetBytes(in []byte) *Scalar {
	s.s.SetBytes(in)
	s.s.Mod(&s.s, Q)
	return s
}

// Bytes returns the canonical 32 bytes little-endian encoding of s.
func (s *Scalar) Bytes() []byte {
	buf := make([]byte, params.BytesScalar)
	return s.s.FillBytes(buf)
}

// Equal returns 1 if s and t are equal, and 0 otherwise.
func (s *Scalar) Equal(t *Scalar) int {
	if s.s.Cmp(&t.s) == 0 {
		return 1
	}
	return 0
}

// Invert sets s to the inverse of a nonzero scalar v, and returns s.
//
// If t is zero, Invert will panic.
func (s *Scalar) Invert(t *Scalar) *Scalar {
	s.s.ModInverse(&t.s, Q)
	return s
}

// Random sets s to a random value.
func (s *Scalar) Random() *Scalar {
	n, err := rand.Int(rand.Reader, Q)
	if err != nil {
		panic("failed to generate random Point")
	}
	s.s.Set(n)
	return s
}

func (s *Scalar) IsZero() bool {
	return s.s.Sign() == 0
}

// NewScalarRandom returns a new Scalar in the correct range, and panics if
// the sampling failed
func NewScalarRandom() *Scalar {
	var s Scalar
	return s.Random()
}

func (s *Scalar) BigInt() *big.Int {
	return &s.s
}
