package zkelog

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
)

func TestELog(t *testing.T) {
	h := new(curve.Point).ScalarBaseMult(curve.NewScalarRandom())

	X := new(curve.Point).ScalarBaseMult(curve.NewScalarRandom())

	y := curve.NewScalarRandom()
	Y := new(curve.Point).ScalarMult(y, h)

	lambda := curve.NewScalarRandom()
	L := new(curve.Point).ScalarBaseMult(lambda)

	M := new(curve.Point).ScalarMult(lambda, X)
	M.Add(M, new(curve.Point).ScalarBaseMult(y))

	proof := NewProof(h, X, L, M, Y, lambda, y)
	if !proof.Verify(h, X, L, M, Y) {
		t.Error("failed to verify")
	}
}
