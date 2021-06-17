package signature

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
)

func NewSignature(x *curve.Scalar, hash []byte, k *curve.Scalar) *Signature {
	if k == nil {
		k = sample.Scalar()
	}
	m := curve.NewScalar().SetHash(hash)
	kInv := curve.NewScalar().Invert(k)
	R := curve.NewIdentityPoint().ScalarBaseMult(kInv)
	r := R.XScalar()
	s := curve.NewScalar().MultiplyAdd(x, r, m)
	s.Multiply(s, k)
	return &Signature{
		R: R,
		S: s,
	}
}

func TestSignature_Verify(t *testing.T) {
	m := []byte("hello")
	x := sample.Scalar()
	X := curve.NewIdentityPoint().ScalarBaseMult(x)
	sig := NewSignature(x, m, nil)
	if !sig.Verify(X, m) {
		t.Error("verify failed")
	}
}
