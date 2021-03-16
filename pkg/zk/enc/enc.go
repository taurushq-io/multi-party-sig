package zkenc

import (
	"fmt"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/pedersen"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/zkcommon"
)

const domain = "CMP-ENC"

type Commitment struct {
	// A = Enc(alpha; r)
	A *paillier.Ciphertext

	// S = s^k t^mu
	// C = s^alpha t^gamma
	S, C *big.Int
}

type Response struct {
	// Z1 = alpha + e•k
	// Z2 = r rho^e (mod N0)
	// Z3 = gamma + e•mu
	Z1, Z2, Z3 *big.Int
}

type Proof struct {
	*Commitment
	*Response
}

func (commitment *Commitment) Challenge() *big.Int {
	return zkcommon.MakeChallengeFq(domain, commitment.A, commitment.S, commitment.C)
}

// NewProof generates a proof that the
func NewProof(
	prover *paillier.PublicKey, verifier *pedersen.Verifier, K *paillier.Ciphertext,
	k, rho *big.Int) *Proof {
	N := prover.N()

	alpha := arith.Sample(arith.LPlusEpsilon, false)
	mu := arith.Sample(arith.L, true)
	gamma := arith.Sample(arith.LPlusEpsilon, true)

	A, r := prover.Enc(alpha, nil)

	commitment := &Commitment{
		A: A,
		S: verifier.Commit(k, mu),
		C: verifier.Commit(alpha, gamma),
	}

	e := commitment.Challenge()

	var z1, z2, z3 big.Int
	z1.Mul(e, k)
	z1.Add(&z1, alpha)

	z2.Exp(rho, e, N)
	z2.Mul(&z2, r)
	z2.Mod(&z2, N)

	z3.Mul(e, mu)
	z3.Add(&z3, gamma)

	response := &Response{
		Z1: &z1,
		Z2: &z2,
		Z3: &z3,
	}

	return &Proof{
		Commitment: commitment,
		Response:   response,
	}
}

func (proof *Proof) Verify(prover *paillier.PublicKey, verifier *pedersen.Verifier, K *paillier.Ciphertext) bool {
	e := proof.Challenge()

	var rhsCt paillier.Ciphertext
	lhsCt, _ := prover.Enc(proof.Z1, proof.Z2)
	rhsCt.Mul(prover, K, e)
	rhsCt.Add(prover, &rhsCt, proof.A)
	if !lhsCt.Equal(&rhsCt) {
		fmt.Println("fail ct")
		return false
	}

	if !verifier.Verify(proof.Z1, proof.Z3, proof.C, proof.S, e) {
		fmt.Println("fail ped")
		return false
	}

	return true
}
