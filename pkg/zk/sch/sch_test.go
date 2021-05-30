package zksch

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

func TestSch(t *testing.T) {
	x := curve.NewScalarRandom()
	X := new(curve.Point).ScalarBaseMult(x)
	a := curve.NewScalarRandom()
	A := new(curve.Point).ScalarBaseMult(a)

	proof, err := Prove(hash.New(), A, X, a, x)
	if err != nil {
		t.Error(err)
	}
	if !Verify(hash.New(), A, X, proof) {
		t.Error("failed to verify")
	}
}
