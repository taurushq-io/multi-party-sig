package zksch

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
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
	return hash.ReadScalar()
}

func challengeMult(h *hash.Hash, As, Xs []curve.Point) []*curve.Scalar {
	t := len(Xs)
	for l := 0; l < t; l++ {
		_, _ = h.WriteAny(&As[l], &Xs[l])
	}
	es := make([]*curve.Scalar, t)
	for l := range es {
		es[l] = h.ReadScalar()
	}
	return es
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
