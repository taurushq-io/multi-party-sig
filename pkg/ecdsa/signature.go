package ecdsa

import (
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

type Signature struct {
	R curve.Point
	S curve.Scalar
}

// EmptySignature returns a new signature with a given curve, ready to be unmarshalled.
func EmptySignature(group curve.Curve) Signature {
	return Signature{R: group.NewPoint(), S: group.NewScalar()}
}

// Verify is a custom signature format using curve data.
func (sig Signature) Verify(X curve.Point, hash []byte) bool {
	group := X.Curve()

	m := curve.FromHash(group, hash)
	sInv := group.NewScalar().Set(sig.S).Invert()
	mG := m.ActOnBase()
	r := sig.R.XScalar()
	rX := r.Act(X)
	R2 := mG.Add(rX)
	R2 = sInv.Act(R2)
	return R2.Equal(sig.R)
}
