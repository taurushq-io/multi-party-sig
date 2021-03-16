package zkelog

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/zkcommon"
)

const domain = "CMP-ELOG"

type Commitment struct {
	// A = g^alpha
	// N = g^m X^alpha
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

	gm := new(curve.Point).ScalarBaseMult(m)
	N := new(curve.Point).ScalarMult(alpha, X)
	N.Add(N, gm)

	commitment := &Commitment{
		A: new(curve.Point).ScalarBaseMult(alpha),
		N: N,
		B: new(curve.Point).ScalarMult(m, h),
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
	lhs.ScalarBaseMult(proof.Z)
	rhs.ScalarMult(e, L)
	rhs.Add(&rhs, proof.A)

	if lhs.Equal(&rhs) != 1 {
		fmt.Println("fail g")
		return false
	}

	lhs.ScalarMult(proof.Z, X)
	lhs.Add(&lhs, rhs.ScalarBaseMult(proof.U))
	rhs.ScalarMult(e, M)
	rhs.Add(&rhs, proof.N)

	if lhs.Equal(&rhs) != 1 {
		fmt.Println("fail h1")
		return false
	}

	lhs.ScalarMult(proof.U, h)
	rhs.ScalarMult(e, Y)
	rhs.Add(&rhs, proof.B)

	if lhs.Equal(&rhs) != 1 {
		fmt.Println("fail h2")
		return false
	}

	return true
}
