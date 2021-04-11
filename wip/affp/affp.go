package zkaffp

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
	"github.com/taurusgroup/cmp-ecdsa/wip/zkcommon"
)

const domain = "CMP-AFFP"

type Commitment struct {
	// A = (alpha ⊙ c ) ⊕ Enc(N0, beta, r)
	A *paillier.Ciphertext

	// Bx = Enc(N1, alpha, rx)
	// By = Enc(N1, beta, ry)
	Bx, By *paillier.Ciphertext

	// E = s^alpha t^gamma
	// S = sˣ t^m
	E, S *big.Int

	// F = s^beta t^delta
	// T = sʸ t^mu
	F, T *big.Int
}

type Response struct {
	// Z1 = alpha + e•x
	// Z2 = beta + e•y
	// Z3 = gamma + e•m
	// Z4 = delta + e•mu
	Z1, Z2, Z3, Z4 *big.Int

	// W = r • rho^e
	// Wx = rX • rhoX^e
	// WY = rY • rhoY^e
	W, Wx, Wy *big.Int
}

type Proof struct {
	*Commitment
	*Response
}

func (commitment *Commitment) Challenge() *big.Int {
	return zkcommon.MakeChallengeFq(domain, commitment.A, commitment.Bx, commitment.By, commitment.E, commitment.S, commitment.F, commitment.T)
}

// N0 = verifier
// N1 = prover
func NewProof(prover, verifierPaillier *paillier.PublicKey, verifierPedersen *pedersen.Parameters, D, C, X, Y *paillier.Ciphertext,
	x, y, rhoX, rhoY, rho *big.Int) *Proof {

	alpha := sample.PlusMinus(params.LPlusEpsilon, false)
	beta := sample.PlusMinus(params.LPrimePlusEpsilon, false)

	gamma := sample.PlusMinus(params.LPlusEpsilon, true)
	m := sample.PlusMinus(params.L, true)
	delta := sample.PlusMinus(params.LPlusEpsilon, true)
	mu := sample.PlusMinus(params.L, true)

	var Bx, By paillier.Ciphertext
	A, r := verifierPaillier.Enc(beta, nil)
	Bx.Mul(verifierPaillier, C, alpha)
	A.Add(verifierPaillier, A, &Bx)

	_, rx := Bx.Enc(prover, alpha, nil)
	_, ry := By.Enc(prover, beta, nil)

	commitment := &Commitment{
		A:  A,
		Bx: &Bx,
		By: &By,
		E:  verifierPedersen.Commit(alpha, gamma),
		S:  verifierPedersen.Commit(x, m),
		F:  verifierPedersen.Commit(beta, delta),
		T:  verifierPedersen.Commit(y, mu),
	}

	e := commitment.Challenge()

	affine := func(a, b, c *big.Int) *big.Int {
		var result big.Int
		result.Mul(b, c)
		result.Add(&result, a)
		return &result
	}

	affineNonce := func(r, rho, e *big.Int, pk *paillier.PublicKey) *big.Int {
		var result big.Int
		result.Exp(rho, e, pk.N())
		result.Mul(&result, r)
		result.Mod(&result, pk.N())
		return &result
	}

	response := &Response{
		Z1: affine(alpha, e, x),
		Z2: affine(beta, e, y),
		Z3: affine(gamma, e, m),
		Z4: affine(delta, e, mu),
		W:  affineNonce(r, rho, e, verifierPaillier),
		Wx: affineNonce(rx, rhoX, e, prover),
		Wy: affineNonce(ry, rhoY, e, prover),
	}

	return &Proof{
		Commitment: commitment,
		Response:   response,
	}
}

func (proof *Proof) Verify(prover, verifierPaillier *paillier.PublicKey, verifierPedersen *pedersen.Parameters, D, C, X, Y *paillier.Ciphertext) bool {
	if !sample.IsInInterval(proof.Z1, params.LPlusEpsilon) {
		return false
	}
	if !sample.IsInInterval(proof.Z2, params.LPrimePlusEpsilon) {
		return false
	}

	e := proof.Challenge()

	N0 := verifierPaillier
	N1 := prover

	var lhsCt, rhsCt paillier.Ciphertext

	{
		// lhsCt = z1•c + Enc_N0(z2;w)
		rhsCt.Enc(N0, proof.Z2, proof.W)
		lhsCt.Mul(N0, C, proof.Z1)
		lhsCt.Add(N0, &lhsCt, &rhsCt)

		// rhsCt = A + e•D
		rhsCt.Mul(N0, D, e)
		rhsCt.Add(N0, &rhsCt, proof.A)

		if !lhsCt.Equal(&rhsCt) {
			return false
		}
	}

	{
		// lhsCt = Enc_N1(z1;wx)
		lhsCt.Enc(N1, proof.Z1, proof.Wx)

		// rhsCt = Bx + e•X
		rhsCt.Mul(N1, X, e)
		rhsCt.Add(N1, &rhsCt, proof.Bx)

		if !lhsCt.Equal(&rhsCt) {
			return false
		}
	}

	{
		// lhsCt = Enc_N1(z2;wy)
		lhsCt.Enc(N1, proof.Z2, proof.Wy)

		// rhsCt = By + e•Y
		rhsCt.Mul(N1, Y, e)
		rhsCt.Add(N1, &rhsCt, proof.By)

		if !lhsCt.Equal(&rhsCt) {
			return false
		}
	}

	if !verifierPedersen.Verify(proof.Z1, proof.Z3, proof.E, proof.S, e) {
		return false
	}

	if !verifierPedersen.Verify(proof.Z2, proof.Z4, proof.F, proof.T, e) {
		return false
	}

	return true
}
