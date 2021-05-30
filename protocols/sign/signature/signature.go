package signature

import "github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"

type Signature struct {
	R *curve.Point
	S *curve.Scalar
}

func NewSignature(x *curve.Scalar, hash []byte, k *curve.Scalar) *Signature {
	if k == nil {
		k = curve.NewScalarRandom()
	}
	m := curve.NewScalar().SetHash(hash)
	kInv := curve.NewScalar().Invert(k)
	R := curve.NewIdentityPoint().ScalarBaseMult(kInv)
	r := R.X()
	s := curve.NewScalar().MultiplyAdd(x, r, m)
	s.Multiply(s, k)
	return &Signature{
		R: R,
		S: s,
	}
}

func (sig *Signature) Verify(X *curve.Point, hash []byte) bool {
	m := curve.NewScalar().SetHash(hash)
	sInv := curve.NewScalar().Invert(sig.S)
	mG := curve.NewIdentityPoint().ScalarBaseMult(m)
	r := sig.R.X()
	rX := curve.NewIdentityPoint().ScalarMult(r, X)
	R2 := curve.NewIdentityPoint().Add(mG, rX)
	R2.ScalarMult(sInv, R2)
	R2.Subtract(R2, sig.R)
	return R2.IsIdentity()
}
