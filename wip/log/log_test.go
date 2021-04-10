package zklog

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

func TestLog(t *testing.T) {
	r := curve.NewScalarRandom()
	h := new(curve.Point).ScalarBaseMult(r)
	x := curve.NewScalarRandom()
	X := new(curve.Point).ScalarBaseMult(x)
	Y := new(curve.Point).ScalarMult(x, h)
	proof := NewProof(h, X, Y, x)
	if !proof.Verify(h, X, Y) {
		t.Error("failed to verify")
	}
}
