package curve

import (
	"io"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

// Scalar represents an element in ℤₚ where p is the order of the secp256k1 base point.
type Scalar struct {
	s secp256k1.ModNScalar
}

// NewScalar returns a new zero Scalar.
func NewScalar() *Scalar {
	return new(Scalar)
}

// NewScalarBigInt returns a new Scalar from a big.Int.
func NewScalarBigInt(n *big.Int) *Scalar {
	var s Scalar
	return s.SetBigInt(n)
}

// NewScalarInt returns a new Scalar from a safenum.Int.
func NewScalarInt(n *safenum.Int) *Scalar {
	var s Scalar
	return s.SetInt(n)
}

// NewScalarUInt32 returns a new Scalar from a big.Int.
func NewScalarUInt32(n uint32) *Scalar {
	var s Scalar
	return s.SetUInt32(n)
}

// MultiplyAdd sets s = x * y + z mod l, and returns s.
func (s *Scalar) MultiplyAdd(x, y, z *Scalar) *Scalar {
	r := s.s
	r.Mul2(&x.s, &y.s).Add(&z.s)
	s.s = r
	return s
}

// Add sets s = x + y mod l, and returns s.
func (s *Scalar) Add(x, y *Scalar) *Scalar {
	r := s.s
	r.Add2(&x.s, &y.s)
	s.s = r
	return s
}

// Subtract sets s = x - y mod l, and returns s.
func (s *Scalar) Subtract(x, y *Scalar) *Scalar {
	r := y.s
	r.Negate().Add(&x.s)
	s.s = r
	return s
}

// Negate sets s = -x mod l, and returns s.
func (s *Scalar) Negate(x *Scalar) *Scalar {
	s.s = x.s
	s.s.Negate()
	return s
}

// Multiply sets s = x * y mod l, and returns s.
func (s *Scalar) Multiply(x, y *Scalar) *Scalar {
	r := s.s
	r.Mul2(&x.s, &y.s)
	s.s = r
	return s
}

// Set sets s = x, and returns s.
func (s *Scalar) Set(x *Scalar) *Scalar {
	s.s = x.s
	return s
}

// SetUInt32 sets s = x, and returns s.
func (s *Scalar) SetUInt32(i uint32) *Scalar {
	s.s.SetInt(i)
	return s
}

// SetBigInt sets s = i mod q, and returns s.
func (s *Scalar) SetBigInt(i *big.Int) *Scalar {
	var n big.Int
	n.Set(i)
	if n.CmpAbs(q) != -1 {
		n.Mod(i, q)
	}
	if n.Sign() == -1 {
		n.Add(&n, q)
	}
	s.s.SetByteSlice(n.Bytes())
	return s
}

// SetInt sets s = i mod q, returning s.
func (s *Scalar) SetInt(i *safenum.Int) *Scalar {
	s.s.SetByteSlice(i.Mod(qMod).Bytes())
	return s
}

// SetBytes sets s = x, and returns s.
func (s *Scalar) SetBytes(in []byte) (*Scalar, bool) {
	overflowed := s.s.SetByteSlice(in)
	return s, !overflowed
}

// SetHash converts a hash value to a Scalar. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
//
// Taken from crypto/ecdsa.
func (s *Scalar) SetHash(hash []byte) *Scalar {
	i := new(big.Int)
	orderBits := q.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	i.SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		i.Rsh(i, uint(excess))
	}
	s.SetBigInt(i)
	return s
}

// Equal returns 1 if s and t are equal, and 0 otherwise.
func (s *Scalar) Equal(t *Scalar) bool {
	return s.s.Equals(&t.s)
}

// Invert sets s to the inverse of a nonzero scalar v, and returns s.
//
// If t is zero, Invert will panic.
func (s *Scalar) Invert(t *Scalar) *Scalar {
	s.s.InverseValNonConst(&t.s)
	return s
}

// IsZero returns true if s ≡ 0.
func (s *Scalar) IsZero() bool {
	return s.s.IsZero()
}

// BigInt returns s as a *big.Int.
func (s *Scalar) BigInt() *big.Int {
	var i big.Int
	b := s.s.Bytes()
	i.SetBytes(b[:])
	return &i
}

// Int returns s as a *safenum.Int.
func (s *Scalar) Int() *safenum.Int {
	b := s.s.Bytes()
	return new(safenum.Int).SetBytes(b[:])
}

// Bytes returns the 32 bytes that make up this scalar, in Big Endian order
func (s *Scalar) Bytes() [32]byte {
	return s.s.Bytes()
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (s *Scalar) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, params.BytesScalar)
	if _, err := s.MarshalTo(buf); err != nil {
		return 0, err
	}
	n, err := w.Write(buf)
	return int64(n), err
}

// Domain implements WriterToWithDomain, and separates this type within hash.Hash.
func (*Scalar) Domain() string {
	return "Scalar"
}
