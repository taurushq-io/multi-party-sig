package signature

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

func TestSignature_Verify(t *testing.T) {
	m := []byte("hello")
	x := curve.NewScalarRandom()
	X := curve.NewIdentityPoint().ScalarBaseMult(x)
	sig := NewSignature(x, m, nil)
	if !sig.Verify(X, m) {
		t.Error("verify failed")
	}
}
