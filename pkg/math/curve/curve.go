package curve

import (
	"encoding"

	"github.com/cronokirby/safenum"
)

type Curve interface {
	NewPoint() Point
	NewBasePoint() Point
	NewScalar() Scalar
	Name() string
	SafeScalarBytes() int
	Order() *safenum.Modulus
}

type Scalar interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Curve() Curve
	Add(Scalar) Scalar
	Sub(Scalar) Scalar
	Negate() Scalar
	Mul(Scalar) Scalar
	Invert() Scalar
	Equal(Scalar) bool
	IsZero() bool
	Set(Scalar) Scalar
	SetNat(*safenum.Nat) Scalar
	Act(Point) Point
	ActOnBase() Point
}

type Point interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Curve() Curve
	Add(Point) Point
	Sub(Point) Point
	Negate() Point
	Set(Point) Point
	Equal(Point) bool
	IsIdentity() bool
	XScalar() Scalar
}

func MakeInt(s Scalar) *safenum.Int {
	bytes, err := s.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return new(safenum.Int).SetBytes(bytes)
}

// FromHash converts a hash value to a Scalar.
//
// There is some disagreement about how this should be done.
// [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
//
// Taken from crypto/ecdsa.
func FromHash(group Curve, h []byte) Scalar {
	order := group.Order()
	orderBits := order.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(h) > orderBytes {
		h = h[:orderBytes]
	}
	s := new(safenum.Nat).SetBytes(h)
	excess := len(h)*8 - orderBits
	if excess > 0 {
		s.Rsh(s, uint(excess), -1)
	}
	return group.NewScalar().SetNat(s)
}
