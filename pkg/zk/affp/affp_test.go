package affp

import (
	"math/big"
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/pedersen"
)

func TestAffP(t *testing.T) {
	verifierPaillier, sk := paillier.KeyGen(arith.SecParam)
	verifierPedersen := pedersen.NewPedersen(verifierPaillier.N(), sk.Phi())
	prover, _ := paillier.KeyGen(arith.SecParam)
	x := arith.Sample(arith.L, nil)
	y := arith.Sample(arith.LPrime, nil)
	c := big.NewInt(12)

	C, _ := verifierPaillier.Enc(c, nil)
	X, rhoX := prover.Enc(x, nil)
	Y, rhoY := prover.Enc(y, nil)

	var tmp paillier.Ciphertext
	tmp.Mul(verifierPaillier, C, x)
	D, rho := verifierPaillier.Enc(y, nil)
	D.Add(verifierPaillier, D, &tmp)

	proof := NewProof(prover, verifierPaillier, verifierPedersen, D, C, X, Y, x, y, rhoX, rhoY, rho)
	if !proof.Verify(prover, verifierPaillier, verifierPedersen, D, C, X, Y) {
		t.Error("failed to verify")
	}
}
