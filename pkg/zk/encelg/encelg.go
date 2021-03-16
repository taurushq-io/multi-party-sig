package zkencelg

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/pedersen"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/zkcommon"
)

const domain = "CMP-ENC-ELG"

type Commitment struct {
	// S = s^x t^mu (mod NHat)
	// T = s^alpha t^gamma (mod NHat)
	S, T *big.Int

	// D = Enc(N0, alpha, r)
	D *paillier.Ciphertext

	// Y = A^beta g^alpha
	// Z = g^beta
	Y, Z *curve.Point
}

type Response struct {
	// Z1 = alpha + e•x
	// Z2 = r•rho^e (mod N0)
	// Z3 = gamma + e•mu
	Z1, Z2, Z3 *big.Int

	// W = beta + e•b (mod q)
	W *curve.Scalar
}

type Proof struct {
	*Commitment
	*Response
}

func (commitment *Commitment) Challenge() *big.Int {
	return zkcommon.MakeChallengeFq(domain, commitment.S, commitment.T, commitment.D, commitment.Y, commitment.Z)
}

// N0 = prover
// NHat = verifier
func NewProof(prover *paillier.PublicKey, verifier *pedersen.Verifier, C *paillier.Ciphertext, A, B, X *curve.Point,
	x, rho *big.Int, a, b *curve.Scalar) *Proof {

	alpha := arith.Sample(arith.LPlusEpsilon, false)
	mu := arith.Sample(arith.L, true)
	gamma := arith.Sample(arith.LPlusEpsilon, true)
	beta := curve.NewScalarRandom()

	S := verifier.Commit(x, mu)
	T := verifier.Commit(alpha, gamma)
	D, r := prover.Enc(alpha, nil)

	var Y, Z curve.Point
	Y.ScalarMult(beta, A)
	Z.ScalarBaseMult(curve.NewScalarBigInt(alpha)) // Use Z as temp variable
	Y.Add(&Y, &Z)

	Z.ScalarBaseMult(beta)

	commitment := &Commitment{
		S: S,
		T: T,
		D: D,
		Y: &Y,
		Z: &Z,
	}

	e := commitment.Challenge()

	var z1, z2, z3 big.Int
	z1.Mul(e, x)
	z1.Add(&z1, alpha)

	var w curve.Scalar
	w.MultiplyAdd(curve.NewScalarBigInt(e), b, beta)

	z2.Exp(rho, e, prover.N())
	z2.Mul(&z2, r)
	z2.Mod(&z2, prover.N())

	z3.Mul(e, mu)
	z3.Add(&z3, gamma)

	response := &Response{
		Z1: &z1,
		Z2: &z2,
		Z3: &z3,
		W:  &w,
	}
	return &Proof{
		Commitment: commitment,
		Response:   response,
	}
}

func (proof *Proof) Verify(prover *paillier.PublicKey, verifier *pedersen.Verifier, C *paillier.Ciphertext, A, B, X *curve.Point) bool {
	if !arith.IsInInterval(proof.Z1, arith.LPlusEpsilon) {
		return false
	}

	e := proof.Challenge()

	{
		var lhs, rhs paillier.Ciphertext
		lhs.Enc(prover, proof.Z1, proof.Z2)

		rhs.Mul(prover, C, e)
		rhs.Add(prover, &rhs, proof.D)
		if !lhs.Equal(&rhs) {
			return false
		}
	}

	eScalar := curve.NewScalarBigInt(e)

	var lhsPoint, rhsPoint curve.Point
	{
		lhsPoint.ScalarMult(proof.W, A)
		rhsPoint.ScalarBaseMult(curve.NewScalarBigInt(proof.Z1)) // use rhsPoint as temp receiver
		lhsPoint.Add(&lhsPoint, &rhsPoint)

		rhsPoint.ScalarMult(eScalar, X)
		rhsPoint.Add(&rhsPoint, proof.Y)
		if lhsPoint.Equal(&rhsPoint) != 1 {
			return false
		}
	}

	{
		lhsPoint.ScalarBaseMult(proof.W)
		rhsPoint.ScalarMult(eScalar, B)
		rhsPoint.Add(&rhsPoint, proof.Z)
		if lhsPoint.Equal(&rhsPoint) != 1 {
			return false
		}
	}

	{
		if !verifier.Verify(proof.Z1, proof.Z3, proof.T, proof.S, e) {
			return false
		}
	}

	return true
}
