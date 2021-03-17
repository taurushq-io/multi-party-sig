package zkencelg

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/zkcommon"
)

func TestEncElg(t *testing.T) {
	verifier := zkcommon.Pedersen
	prover := zkcommon.ProverPaillierPublic
	x := sample.PlusMinus(params.L, false)
	C, rho := prover.Enc(x, nil)

	a := curve.NewScalarRandom()
	b := curve.NewScalarRandom()
	c := curve.NewScalar()
	c.MultiplyAdd(a, b, curve.NewScalarBigInt(x))
	var A, B, X curve.Point
	A.ScalarBaseMult(a)
	B.ScalarBaseMult(b)
	X.ScalarBaseMult(c)

	proof := NewProof(prover, verifier, C, &A, &B, &X, x, rho, a, b)
	if !proof.Verify(prover, verifier, C, &A, &B, &X) {
		t.Error("failed to verify")
	}
}
