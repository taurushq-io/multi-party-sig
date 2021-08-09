package curve

import (
	"encoding"

	"github.com/cronokirby/safenum"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

// q is the order of the base point.
var q = secp256k1.S256().Params().N
var qMod = safenum.ModulusFromNat(new(safenum.Nat).SetBig(q, q.BitLen()))

type Curve interface {
	NewPoint() PointI
	NewScalar() ScalarI
}

type ScalarI interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Add(ScalarI) ScalarI
	Mul(ScalarI) ScalarI
	Invert() ScalarI
	Negate() ScalarI
	Equal(ScalarI) bool
	IsZero() bool
	Set(ScalarI) ScalarI
	SetNat(*safenum.Nat) ScalarI
	Act(PointI) PointI
	ActOnBase() PointI
}

type PointI interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Add(PointI) PointI
	Negate() PointI
	Equal(PointI) bool
}
