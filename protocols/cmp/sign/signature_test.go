package sign

import (
	"crypto/rand"
	"testing"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

func NewSignature(x *curve.Scalar, hash []byte, k *curve.Scalar) *Signature {
	if k == nil {
		k = sample.Scalar(rand.Reader)
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
	x := sample.Scalar(rand.Reader)
	X := curve.NewIdentityPoint().ScalarBaseMult(x)
	sig := NewSignature(x, m, nil)
	if !sig.Verify(X, m) {
		t.Error("verify failed")
	}
}
