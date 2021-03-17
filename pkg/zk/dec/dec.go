package zkdec

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/pedersen"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/zkcommon"
)

const domain = "CMP-DEC"

type Commitment struct {
	// A = Enc_N0(alpha; r)
	A *paillier.Ciphertext

	// Gamma = alpha (mod q)
	Gamma *curve.Scalar

	// S = s^y t^mu
	// T = s^alpha t^nu
	S, T *big.Int
}

type Response struct {
	// Z1 = alpha + e•y
	// Z2 = nu + e•mu
	// W  = r rho^e (mod N0)
	Z1, Z2, W *big.Int
}

type Proof struct {
	*Commitment
	*Response
}

func (commitment *Commitment) Challenge() *big.Int {
	return zkcommon.MakeChallengeFq(domain, commitment.A, commitment.Gamma, commitment.S, commitment.T)
}

// NewProof generates a proof that the
func NewProof(
	prover *paillier.PublicKey, verifier *pedersen.Verifier, C *paillier.Ciphertext, x *curve.Scalar,
	y, rho *big.Int) *Proof {
	alpha := sample.PlusMinus(params.LPlusEpsilon, false)
	mu := sample.PlusMinus(params.L, true)
	nu := sample.PlusMinus(params.LPlusEpsilon, true)

	A, r := prover.Enc(alpha, nil)

	commitment := &Commitment{
		A:     A,
		Gamma: curve.NewScalarBigInt(alpha),
		S:     verifier.Commit(y, mu),
		T:     verifier.Commit(alpha, nu),
	}

	e := commitment.Challenge()

	var z1, z2, w big.Int
	z1.Mul(e, y)
	z1.Add(&z1, alpha)

	z2.Mul(e, mu)
	z2.Add(&z2, nu)

	N0 := prover.N()
	w.Exp(rho, e, N0)
	w.Mul(&w, r)
	w.Mod(&w, N0)

	response := &Response{
		Z1: &z1,
		Z2: &z2,
		W:  &w,
	}

	return &Proof{
		Commitment: commitment,
		Response:   response,
	}
}

func (proof *Proof) Verify(prover *paillier.PublicKey, verifier *pedersen.Verifier, C *paillier.Ciphertext, x *curve.Scalar) bool {
	e := proof.Challenge()

	{
		var lhs, rhs paillier.Ciphertext
		// lhs = Enc_N0(z1, w)
		lhs.Enc(prover, proof.Z1, proof.W)

		// rhs = A C^e
		rhs.Mul(prover, C, e)
		rhs.Add(prover, &rhs, proof.A)

		if !lhs.Equal(&rhs) {
			return false
		}
	}

	{
		var lhs, rhs curve.Scalar
		lhs.SetBigInt(proof.Z1)

		rhs.MultiplyAdd(curve.NewScalarBigInt(e), x, proof.Gamma)

		if lhs.Equal(&rhs) != 1 {
			return false
		}
	}

	{
		if !verifier.Verify(proof.Z1, proof.Z2, proof.T, proof.S, e) {
			return false
		}
	}

	return true
}
