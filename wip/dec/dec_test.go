package zkdec

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/wip/zkcommon"
)

func TestDec(t *testing.T) {
	verifier := zkcommon.Pedersen
	prover := zkcommon.ProverPaillierPublic

	y := sample.PlusMinus(params.L, false)
	x := curve.NewScalarBigInt(y)

	C, rho := prover.Enc(y, nil)

	proof := NewProof(prover, verifier, C, x, y, rho)
	if !proof.Verify(prover, verifier, C, x) {
		t.Error("failed to verify")
	}
}
