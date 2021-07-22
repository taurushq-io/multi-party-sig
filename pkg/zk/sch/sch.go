package zksch

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
)

type Commitment struct {
	// A = gᵃ
	A *curve.Point
}

type Response struct {
	// Z = a + ex
	Z *curve.Scalar
}

type Proof struct {
	*Commitment
	*Response
}

func challenge(hash *hash.Hash, A, X *curve.Point) *curve.Scalar {
	_, _ = hash.WriteAny(A, X)
	return sample.Scalar(hash)
}

func Prove(hash *hash.Hash, A, X *curve.Point, a, x *curve.Scalar) *curve.Scalar {
	proof := challenge(hash, A, X)
	proof.MultiplyAdd(proof, x, a)
	return proof
}

func Verify(hash *hash.Hash, A, X *curve.Point, proof *curve.Scalar) bool {
	if A == nil || X == nil {
		return false
	}

	if A.IsIdentity() || X.IsIdentity() {
		return false
	}

	e := challenge(hash, A, X)

	var lhs, rhs curve.Point
	lhs.ScalarBaseMult(proof)
	rhs.ScalarMult(e, X)
	rhs.Add(&rhs, A)

	return lhs.Equal(&rhs)
}
