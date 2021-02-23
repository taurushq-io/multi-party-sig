package affp

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/secp256k1"
)

func TestSch(t *testing.T) {
	x := secp256k1.NewScalarRandom()
	X := new(secp256k1.Point).ScalarBaseMult(x)
	proof := NewProof(X, x)
	if !proof.Verify(X) {
		t.Error("failed to verify")
	}
}
