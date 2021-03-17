package zkmulg

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/zkcommon"
)

func TestMulG(t *testing.T) {
	pk := zkcommon.ProverPaillierPublic
	verif := zkcommon.Pedersen
	x := sample.PlusMinus(params.L, false)
	X := curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarBigInt(x))

	C, _ := pk.Enc(sample.PlusMinus(params.LPlusEpsilon, false), nil)

	var D paillier.Ciphertext
	D.Mul(pk, C, x)
	_, rho := D.Randomize(pk, nil)

	proof := NewProof(pk, verif, C, &D, X, x, rho)
	if !proof.Verify(pk, verif, C, &D, X) {
		t.Error("failed to verify")
	}
}
