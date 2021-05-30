package zkmulg

import (
	"io"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
	"github.com/taurusgroup/cmp-ecdsa/wip/zkcommon"
)

const domain = "CMP-MULG"

type Commitment struct {
	// A = (alpha ⊙ c ) • r^N0
	A *paillier.Ciphertext

	// Bx = g^alpha
	Bx *curve.Point

	// E = s^alpha t^gamma (mod NHat)
	// S = sˣ tᵐ (mod NHat)
	E, S *big.Int
}

func (commitment *Commitment) WriteTo(w io.Writer) (n int64, err error) {
	var n2 int
	n2, err = w.Write(commitment.A.Bytes())
	n += int64(n2)
	if err != nil {
		return
	}
	n2, err = w.Write(commitment.Bx.Bytes())
	n += int64(n2)
	if err != nil {
		return
	}
	n2, err = w.Write(commitment.E.Bytes())
	n += int64(n2)
	if err != nil {
		return
	}
	n2, err = w.Write(commitment.S.Bytes())
	n += int64(n2)
	if err != nil {
		return
	}
	return
}

type Response struct {
	// Z1 = alpha + e•x
	// Z2 = gamma + e•m
	// W  = r rhoᵉ (mod N0)
	Z1, Z2, W *big.Int
}

type Proof struct {
	*Commitment
	*Response
}

func (commitment *Commitment) Challenge() *big.Int {
	return zkcommon.MakeChallengeFq(domain, commitment.A, commitment.Bx, commitment.E, commitment.S)
}

// NewProof generates a proof that the
// x ∈ ±2^l
// gˣ = X
// D = (alpha ⊙ c ) • rho^N0
func NewProof(proverPailler *paillier.PublicKey, verifierPedersen *pedersen.Parameters, C, D *paillier.Ciphertext, X *curve.Point,
	x, rho *big.Int) *Proof {
	alpha := sample.PlusMinus(params.LPlusEpsilon, false)
	r := proverPailler.Nonce()
	gamma := sample.PlusMinus(params.LPlusEpsilon, true)
	m := sample.PlusMinus(params.L, true)

	var A paillier.Ciphertext
	A.Mul(proverPailler, C, alpha)
	A.Randomize(proverPailler, r)

	var Bx curve.Point
	Bx.ScalarBaseMult(curve.NewScalarBigInt(alpha))

	commitment := &Commitment{
		A:  &A,
		Bx: &Bx,
		E:  verifierPedersen.Commit(alpha, gamma),
		S:  verifierPedersen.Commit(x, m),
	}

	e := commitment.Challenge()

	var z1, z2, w big.Int
	z1.Mul(e, x)
	z1.Add(&z1, alpha)

	z2.Mul(e, m)
	z2.Add(&z2, gamma)

	N0 := proverPailler.N
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

func (proof *Proof) Verify(proverPailler *paillier.PublicKey, verifierPedersen *pedersen.Parameters, C, D *paillier.Ciphertext, X *curve.Point) bool {
	if !sample.IsInInterval(proof.Z1, params.LPlusEpsilon) {
		return false
	}

	e := proof.Challenge()

	{
		var lhs, rhs paillier.Ciphertext
		// lhs = c^z1 w^N0
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
