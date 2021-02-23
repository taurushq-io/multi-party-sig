package affp

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/secp256k1"
)

func TestLog(t *testing.T) {
	r := secp256k1.NewScalarRandom()
	h := new(secp256k1.Point).ScalarBaseMult(r)
	x := secp256k1.NewScalarRandom()
	X := new(secp256k1.Point).ScalarBaseMult(x)
	Y := new(secp256k1.Point).ScalarMult(x, h)
	proof := NewProof(h, X, Y, x)
	if !proof.Verify(h, X, Y) {
		t.Error("failed to verify")
	}
}
