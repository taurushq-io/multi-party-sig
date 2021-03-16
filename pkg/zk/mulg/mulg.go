package zkmulg

import (
	"crypto/sha512"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/pedersen"
)

const domain = "CMP-MULG"

type Commitment struct {
	// A = (alpha ⊙ C ) • r^N0
	A *paillier.Ciphertext

	// Bx = g^alpha
	Bx *curve.Point

	// E = s^alpha t^gamma (mod NHat)
	// S = s^x t^m (mod NHat)
	E, S *big.Int
}

type Response struct {
	// Z1 = alpha + e•x
	// Z2 = gamma + e•m
	// W  = r rho^e (mod N0)
	Z1, Z2, W *big.Int
}

type Proof struct {
	*Commitment
	*Response
}

func (commitment *Commitment) Challenge() *big.Int {
	var e big.Int
	h := sha512.New()
	h.Write([]byte(domain))

	// TODO Which parameters should we include?
	// Write public parameters to hash
	h.Write([]byte(""))

	// Write commitments
	h.Write(commitment.A.Bytes())
	h.Write(commitment.Bx.Bytes())
	h.Write(commitment.E.Bytes())
	h.Write(commitment.S.Bytes())

	out := h.Sum(nil)
	e.SetBytes(out)
	e.Mod(&e, curve.Q)
	e.Sub(&e, curve.QHalf)
	return &e
}

// NewProof generates a proof that the
// x ∈ ±2^l
// g^x = X
// D = (alpha ⊙ C ) • rho^N0
func NewProof(proverPailler *paillier.PublicKey, verifierPedersen *pedersen.Verifier, C, D *paillier.Ciphertext, X *curve.Point,
	x, rho *big.Int) *Proof {
	alpha := arith.Sample(arith.LPlusEpsilon, false)
	r := proverPailler.Nonce()
	gamma := arith.Sample(arith.LPlusEpsilon, true)
	m := arith.Sample(arith.L, true)

	var A paillier.Ciphertext
	A.Mul(proverPailler, C, alpha)
	A.Randomize(proverPailler, r)

	var Bx curve.Point
	Bx.ScalarBaseMult(curve.NewScalarBigInt(alpha))

	commitment := &Commitment{
		A: &A,
		Bx: &Bx,
		E: verifierPedersen.Commit(alpha, gamma, nil),
		S: verifierPedersen.Commit(x, m, nil),
	}

	e := commitment.Challenge()

	var z1, z2, w big.Int
	z1.Mul(e, x)
	z1.Add(&z1, alpha)

	z2.Mul(e, m)
	z2.Add(&z2, gamma)

	N0 := proverPailler.N()
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

func (proof *Proof) Verify(proverPailler *paillier.PublicKey, verifierPedersen *pedersen.Verifier, C, D *paillier.Ciphertext, X *curve.Point) bool {
	e := proof.Challenge()

	{
		var lhs, rhs paillier.Ciphertext
		// lhs = C^z1 w^N0
		lhs.Mul(proverPailler, C, proof.Z1)
		lhs.Randomize(proverPailler, proof.W)

		// rhs = A D^e
		rhs.Mul(proverPailler, D, e)
		rhs.Add(proverPailler, &rhs, proof.A)

		if !lhs.Equal(&rhs) {
			return false
		}
	}

	{
		var lhs, rhs curve.Point
		// lhs = g^z1
		lhs.ScalarBaseMult(curve.NewScalarBigInt(proof.Z1))

		// rhs = Bx X^e
		rhs.ScalarMult(curve.NewScalarBigInt(e), X)
		rhs.Add(&rhs, proof.Bx)
		if lhs.Equal(&rhs) != 1 {
			return false
		}
	}

	{
		 if !verifierPedersen.Verify(proof.Z1, proof.Z2, proof.E, proof.S, e) {
			 return false
		 }
	}


	return true
}
