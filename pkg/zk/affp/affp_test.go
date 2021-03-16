package zkaffp

import (
	"math/big"
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/zkcommon"
)

//func TestAP(t *testing.T) {
//	ProverPaillierPublic, ProverPaillierSecret := paillier.KeyGen(arith.SecParam)
//	VerifierPaillierPublic, VerifierPaillierSecret := paillier.KeyGen(arith.SecParam)
//	Pedersen := pedersen.NewPedersen(VerifierPaillierPublic.N(), VerifierPaillierSecret.Phi())
//
//	fmt.Printf("ProverPaillierPublic %x\n", ProverPaillierPublic.N())
//	fmt.Printf("ProverPaillierSecret %x\n", ProverPaillierSecret.Phi())
//	fmt.Printf("VerifierPaillierPublic %x\n", VerifierPaillierPublic.N())
//	fmt.Printf("VerifierPaillierSecret %x\n", VerifierPaillierSecret.Phi())
//	fmt.Printf("PedersenS %x\n", Pedersen.S)
//	fmt.Printf("PedersenT %x\n\n", Pedersen.T)
//}

func TestAffP(t *testing.T) {
	verifierPaillier := zkcommon.VerifierPaillierPublic
	verifierPedersen := zkcommon.Pedersen
	prover := zkcommon.ProverPaillierPublic
	x := arith.Sample(arith.L, false)
	y := arith.Sample(arith.LPrime, false)
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
