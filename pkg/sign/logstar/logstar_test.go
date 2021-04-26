package zklogstar

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/wip/zkcommon"
)

func TestLogStar(t *testing.T) {
	verifier := zkcommon.Pedersen
	prover := zkcommon.ProverPaillierPublic

	x := sample.PlusMinus(params.L, false)
	C, rho := prover.Enc(x, nil)

	var X, H curve.Point
	h := curve.NewScalarRandom()
	H.ScalarBaseMult(h)

	X.ScalarMult(curve.NewScalarBigInt(x), &H)

	proof := NewProof(prover, verifier, C, &X, &H, x, rho)
	if !proof.Verify(prover, verifier, C, &X, &H) {
		t.Error("failed to verify")
	}
}
