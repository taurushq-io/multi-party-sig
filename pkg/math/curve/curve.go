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
}

func MakeInt(s Scalar) *safenum.Int {
	bytes, err := s.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return new(safenum.Int).SetBytes(bytes)
}
