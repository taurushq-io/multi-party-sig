package ecdsa

import (
	"crypto/rand"
	"testing"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

func NewSignature(x curve.Scalar, hash []byte, k curve.Scalar) *Signature {
	group := x.Curve()

	if k == nil {
		k = sample.Scalar(rand.Reader, group)
	}
	m := curve.FromHash(group, hash)
	kInv := group.NewScalar().Set(k).Invert()
	R := kInv.ActOnBase()
	r := R.XScalar()
	s := r.Mul(x).Add(m).Mul(k)
	return &Signature{
		R: R,
		S: s,
	}
}

func TestSignature_Verify(t *testing.T) {
	group := curve.Secp256k1{}

	m := []byte("hello")
	x := sample.Scalar(rand.Reader, group)
	X := x.ActOnBase()
	sig := NewSignature(x, m, nil)
	if !sig.Verify(X, m) {
		t.Error("verify failed")
	}
}
