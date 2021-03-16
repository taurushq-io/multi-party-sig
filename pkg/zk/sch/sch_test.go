package zksch

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
)

func TestSch(t *testing.T) {
	x := curve.NewScalarRandom()
	X := new(curve.Point).ScalarBaseMult(x)
	proof := NewProof(X, x)
	if !proof.Verify(X) {
		t.Error("failed to verify")
	}
}
