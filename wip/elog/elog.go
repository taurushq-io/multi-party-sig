package zkelog

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/wip/zkcommon"
)

const domain = "CMP-ELOG"

type Commitment struct {
	// A = g^alpha
	// N = gᵐ X^alpha
	// B = h^m
	A, N, B *curve.Point
}

type Response struct {
	// Z = alpha + e lambda
	// U = m + ey
	Z, U *curve.Scalar
}

type Proof struct {
	*Commitment
	*Response
}

func (commitment *Commitment) Challenge() *curve.Scalar {
	return zkcommon.MakeChallengeScalar(domain, commitment.A, commitment.N, commitment.B)
}

// NewProof generates a proof that the
func NewProof(h, X, L, M, Y *curve.Point, lambda, y *curve.Scalar) *Proof {
	alpha := curve.NewScalarRandom()
	m := curve.NewScalarRandom()

	var A, N, B curve.Point
	N.ScalarMult(alpha, X)
	A.ScalarBaseMult(m) // use A temporarily
	N.Add(&N, &A)

	A.ScalarBaseMult(alpha)

	B.ScalarMult(m, h)

	commitment := &Commitment{
		A: &A,
		N: &N,
		B: &B,
	}

	e := commitment.Challenge()

	response := &Response{
		Z: new(curve.Scalar).MultiplyAdd(e, lambda, alpha),
		U: new(curve.Scalar).MultiplyAdd(e, y, m),
	}

	return &Proof{
		Commitment: commitment,
		Response:   response,
	}
}

func (proof *Proof) Verify(h, X, L, M, Y *curve.Point) bool {
	e := proof.Challenge()

	var lhs, rhs curve.Point
	{
		lhs.ScalarBaseMult(proof.Z)
		rhs.ScalarMult(e, L)
		rhs.Add(&rhs, proof.A)

		if lhs.Equal(&rhs) != 1 {
			return false
		}
	}

	{
		lhs.ScalarMult(proof.Z, X)
		lhs.Add(&lhs, rhs.ScalarBaseMult(proof.U))
		rhs.ScalarMult(e, M)
		rhs.Add(&rhs, proof.N)

		if lhs.Equal(&rhs) != 1 {
			return false
		}
	}

	{
		lhs.ScalarMult(proof.U, h)
		rhs.ScalarMult(e, Y)
		rhs.Add(&rhs, proof.B)

		if lhs.Equal(&rhs) != 1 {
			return false
		}
	}

	return true
}
