package zkmulg

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/zkcommon"
)

func TestMulG(t *testing.T) {
	pk := zkcommon.ProverPaillierPublic
	verif := zkcommon.Pedersen
	x := arith.Sample(arith.LPlusEpsilon, false)
	X := curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarBigInt(x))

	C, _ := pk.Enc(arith.Sample(arith.LPlusEpsilon, false), nil)

	var D paillier.Ciphertext
	D.Mul(pk, C, x)
	_, rho := D.Randomize(pk, nil)

	proof := NewProof(pk, verif, C, &D, X, x, rho)
	if !proof.Verify(pk, verif, C, &D, X) {
		t.Error("failed to verify")
	}
}
