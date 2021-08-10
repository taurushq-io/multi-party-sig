package curve

import (
	"encoding"

	"github.com/cronokirby/safenum"
)

type Curve interface {
	NewPoint() Point
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
	SetInt(*safenum.Int) Scalar
	SetUInt32(uint322 uint32) Scalar
	Act(Point) Point
	ActOnBase() Point
}

type Point interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Curve() Curve
	Add(Point) Point
	Negate() Point
	Set(Point) Point
	Equal(Point) bool
	IsIdentity() bool
}
