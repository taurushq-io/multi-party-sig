package affp

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/secp256k1"
)

func TestELog(t *testing.T) {
	h := new(secp256k1.Point).ScalarBaseMult(secp256k1.NewScalarRandom())

	X := new(secp256k1.Point).ScalarBaseMult(secp256k1.NewScalarRandom())

	y := secp256k1.NewScalarRandom()
	Y := new(secp256k1.Point).ScalarMult(y, h)

	lambda := secp256k1.NewScalarRandom()
	L := new(secp256k1.Point).ScalarBaseMult(lambda)

	M := new(secp256k1.Point).ScalarMult(lambda, X)
	M.Add(M, new(secp256k1.Point).ScalarBaseMult(y))




	proof := NewProof(h, X, L, M, Y, lambda, y)
	if !proof.Verify(h, X, L, M, Y) {
		t.Error("failed to verify")
	}
}
