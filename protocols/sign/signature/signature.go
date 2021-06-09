package signature

import "github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"

type Signature struct {
	R *curve.Point
	S *curve.Scalar
}

func (sig *Signature) Verify(X *curve.Point, hash []byte) bool {
	m := curve.NewScalar().SetHash(hash)
	sInv := curve.NewScalar().Invert(sig.S)
	mG := curve.NewIdentityPoint().ScalarBaseMult(m)
	r := sig.R.XScalar()
	rX := curve.NewIdentityPoint().ScalarMult(r, X)
	R2 := curve.NewIdentityPoint().Add(mG, rX)
	R2.ScalarMult(sInv, R2)
	R2.Subtract(R2, sig.R)
	return R2.IsIdentity()
}
