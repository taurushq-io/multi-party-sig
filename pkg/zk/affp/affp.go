package affp

import (
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/secp256k1"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/pedersen"
)

const domainAffP = "CMP-AFFP"

type Commitment struct {
	// A = (alpha ⊙ C ) ⊕ Enc(N0, beta, r)
	A *paillier.Ciphertext

	// Bx = Enc(N1, alpha, rx)
	// By = Enc(N1, beta, ry)
	Bx, By *paillier.Ciphertext

	// E = s^alpha t^gamma
	// S = s^x t^m
	E, S *big.Int

	// F = s^beta t^delta
	// T = s^y t^mu
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
	var e big.Int
	h := sha512.New()
	h.Write([]byte(domainAffP))

	// TODO Which parameters should we include?
	// Write public parameters to hash
	h.Write([]byte(""))

	// Write commitments
	h.Write(commitment.A.Bytes())
	h.Write(commitment.Bx.Bytes())
	h.Write(commitment.By.Bytes())
	h.Write(commitment.E.Bytes())
	h.Write(commitment.S.Bytes())
	h.Write(commitment.F.Bytes())
	h.Write(commitment.T.Bytes())

	out := h.Sum(nil)
	e.SetBytes(out)
	e.Mod(&e, secp256k1.Q)
	e.Sub(&e, secp256k1.QHalf)
	return &e
}

// N0 = verifier
// N1 = prover
func NewProof(prover, verifierPaillier *paillier.PublicKey, verifierPedersen *pedersen.Verifier, D, C, X, Y *paillier.Ciphertext,
	x, y, rhoX, rhoY, rho *big.Int) *Proof {
	var tmpCt paillier.Ciphertext
	var tmp big.Int

	alpha := arith.Sample(arith.LPlusEpsilon, nil)
	beta := arith.Sample(arith.LPrimePlusEpsilon, nil)

	gamma := arith.Sample(arith.LPlusEpsilon, verifierPedersen.N)
	m := arith.Sample(arith.L, verifierPedersen.N)
	delta := arith.Sample(arith.LPlusEpsilon, verifierPedersen.N)
	mu := arith.Sample(arith.L, verifierPedersen.N)

	A, r := verifierPaillier.Enc(beta, nil)
	tmpCt.Mul(verifierPaillier, C, alpha)
	A.Add(verifierPaillier, A, &tmpCt)

	Bx, rx := prover.Enc(alpha, nil)
	By, ry := prover.Enc(beta, nil)

	commitment := &Commitment{
		A:  A,
		Bx: Bx,
		By: By,
		E:  verifierPedersen.Commit(alpha, gamma, &tmp),
		S:  verifierPedersen.Commit(x, m, &tmp),
		F:  verifierPedersen.Commit(beta, delta, &tmp),
		T:  verifierPedersen.Commit(y, mu, &tmp),
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

func (proof *Proof) Verify(prover, verifierPaillier *paillier.PublicKey, verifierPedersen *pedersen.Verifier, D, C, X, Y *paillier.Ciphertext) bool {
	if !arith.IsInInterval(proof.Z1, arith.LPlusEpsilon) {
		fmt.Println(" failed range z1")
		return false
	}
	if !arith.IsInInterval(proof.Z2, arith.LPrimePlusEpsilon) {
		fmt.Println(" failed range z2")
		return false
	}

	e := proof.Challenge()

	N0 := verifierPaillier
	N1 := prover

	var lhsCt, rhsCt paillier.Ciphertext

	{
		// lhsCt = z1•C + Enc_N0(z2;w)
		rhsCt.Enc(N0, proof.Z2, proof.W)
		lhsCt.Mul(N0, C, proof.Z1)
		lhsCt.Add(N0, &lhsCt, &rhsCt)

		// rhsCt = A + e•D
		rhsCt.Mul(N0, D, e)
		rhsCt.Add(N0, &rhsCt, proof.A)

		if !lhsCt.Equal(&rhsCt) {
			fmt.Println("failed ct 1")
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
			fmt.Println("failed ct 2")
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
			fmt.Println("failed ct 3")
			return false
		}
	}

	if !verifierPedersen.Verify(proof.Z1, proof.Z3, proof.E, proof.S, e) {
		fmt.Println("failed ped 1")
		return false
	}

	if !verifierPedersen.Verify(proof.Z2, proof.Z4, proof.F, proof.T, e) {
		fmt.Println("failed ped 2")
		return false
	}

	return true
}
