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
}

type Scalar interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Add(Scalar) Scalar
	Mul(Scalar) Scalar
	Invert() Scalar
	Negate() Scalar
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
	Add(Point) Point
	Negate() Point
	Set(Point) Point
	Equal(Point) bool
}
