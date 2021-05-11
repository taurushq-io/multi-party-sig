package zkmul

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/wip/zkcommon"
)

const domain = "CMP-MUL"

type Commitment struct {
	// A = Y^alpha r^N
	// B = Enc(alpha; s)
	A, B *paillier.Ciphertext
}

type Response struct {
	// Z = alpha + ex
	// U = r • rhoᵉ (mod N)
	// V = s • rhoXᵉ (mod N)
	Z, U, V *big.Int
}

type Proof struct {
	*Commitment
	*Response
}

func (commitment *Commitment) Challenge() *big.Int {
	return zkcommon.MakeChallengeFq(domain, commitment.A, commitment.B)
}

// NewProof generates a proof that the
func NewProof(verifier *paillier.PublicKey, X, Y, C *paillier.Ciphertext,
	x *big.Int, rho, rhoX *big.Int) *Proof {
	N := verifier.N

	alpha := sample.UnitModN(N)

	var A, B paillier.Ciphertext

	A.Mul(verifier, Y, alpha)
	_, r := A.Randomize(verifier, nil)

	_, s := B.Enc(verifier, alpha, nil)

	commitment := &Commitment{
		A: &A,
		B: &B,
	}

	e := commitment.Challenge()

	var z, u, v big.Int
	z.Mul(e, x)
	z.Add(&z, alpha)

	u.Exp(rho, e, N)
	u.Mul(&u, r)

	v.Exp(rhoX, e, N)
	v.Mul(&v, s)
	v.Mod(&v, N)

	response := &Response{
		Z: &z,
		U: &u,
		V: &v,
	}

	return &Proof{
		Commitment: commitment,
		Response:   response,
	}
}

func (proof *Proof) Verify(prover *paillier.PublicKey, X, Y, C *paillier.Ciphertext) bool {
	e := proof.Challenge()

	var lhs, rhs paillier.Ciphertext

	{
		// lhs = Y^z u^N
		lhs.Mul(prover, Y, proof.Z)
		lhs.Randomize(prover, proof.U)

		// rhs = A c^e
		rhs.Mul(prover, C, e)
		rhs.Add(prover, &rhs, proof.A)

		if !lhs.Equal(&rhs) {
			return false
		}
	}

	{
		// lhs = Enc(z; v)
		lhs.Enc(prover, proof.Z, proof.V)

		// rhs = B X^e
		rhs.Mul(prover, X, e)
		rhs.Add(prover, &rhs, proof.B)
		if !lhs.Equal(&rhs) {
			return false
		}
	}

	return true
}
