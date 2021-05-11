package zklogstar

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
	"github.com/taurusgroup/cmp-ecdsa/wip/zkcommon"
)

const domain = "CMP-LOG*"

type Commitment struct {
	// A = Enc_N0(alpha; r)
	A *paillier.Ciphertext

	// Y = g^alpha
	Y *curve.Point

	// S = sˣ t^mu
	// D = s^alpha t^gamma
	S, D *big.Int
}

type Response struct {
	// Z1 = alpha + ex
	// Z2 = r rhoᵉ (mod N0)
	// Z3 = gamma + e mu
	Z1, Z2, Z3 *big.Int
}

type Proof struct {
	*Commitment
	*Response
}

func (commitment *Commitment) Challenge() *big.Int {
	return zkcommon.MakeChallengeFq(domain, commitment.A, commitment.Y, commitment.S, commitment.D)
}

// NewProof generates a proof that the
func NewProof(prover *paillier.PublicKey, verifier *pedersen.Parameters, C *paillier.Ciphertext, X, g *curve.Point,
	x, rho *big.Int) *Proof {
	alpha := sample.PlusMinus(params.LPlusEpsilon, false)
	mu := sample.PlusMinus(params.L, true)
	gamma := sample.PlusMinus(params.LPlusEpsilon, true)

	A, r := prover.Enc(alpha, nil)
	var Y curve.Point
	Y.ScalarMult(curve.NewScalarBigInt(alpha), g)

	commitment := &Commitment{
		A: A,
		Y: &Y,
		S: verifier.Commit(x, mu),
		D: verifier.Commit(alpha, gamma),
	}

	e := commitment.Challenge()

	var z1, z2, z3 big.Int
	z1.Mul(e, x)
	z1.Add(&z1, alpha)

	N0 := prover.N
	z2.Exp(rho, e, N0)
	z2.Mul(&z2, r)
	z2.Mod(&z2, N0)

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

func (proof *Proof) Verify(prover *paillier.PublicKey, verifier *pedersen.Parameters, C *paillier.Ciphertext, X, g *curve.Point) bool {
	if !sample.IsInInterval(proof.Z1, params.LPlusEpsilon) {
		return false
	}

	e := proof.Challenge()

	{
		var lhs, rhs paillier.Ciphertext
		// lhs = Enc_N0(z1; z2)
		lhs.Enc(prover, proof.Z1, proof.Z2)

		// rhs = A c^e
		rhs.Mul(prover, C, e)
		rhs.Add(prover, &rhs, proof.A)

		if !lhs.Equal(&rhs) {
			return false
		}
	}

	{
		var lhs, rhs curve.Point
		lhs.ScalarMult(curve.NewScalarBigInt(proof.Z1), g)

		rhs.ScalarMult(curve.NewScalarBigInt(e), X)
		rhs.Add(&rhs, proof.Y)

		if lhs.Equal(&rhs) != 1 {
			return false
		}
	}

	{
		if !verifier.Verify(proof.Z1, proof.Z3, proof.D, proof.S, e) {
			return false
		}
	}

	return true
}
