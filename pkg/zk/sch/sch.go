package zksch

import (
	"fmt"

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

func challenge(hash *hash.Hash, A, X *curve.Point) (*curve.Scalar, error) {
	if err := hash.WriteAny(A, X); err != nil {
		return nil, fmt.Errorf("challenge: %w", err)
	}
	e, err := hash.ReadScalar()
	if err != nil {
		return nil, fmt.Errorf("challenge: %w", err)
	}
	return e, nil
}

func Prove(hash *hash.Hash, A, X *curve.Point, a, x *curve.Scalar) (proof *curve.Scalar, err error) {
	if proof, err = challenge(hash, A, X); err != nil {
		return nil, fmt.Errorf("zkschnorr: %w", err)
	}
	proof.MultiplyAdd(proof, x, a)
	return
}

func Verify(hash *hash.Hash, A, X *curve.Point, proof *curve.Scalar) bool {
	if A == nil || X == nil {
		return false
	}

	if A.IsIdentity() || X.IsIdentity() {
		return false
	}

	e, err := challenge(hash, A, X)
	if err != nil {
		return false
	}

	var lhs, rhs curve.Point
	lhs.ScalarBaseMult(proof)
	rhs.ScalarMult(e, X)
	rhs.Add(&rhs, A)

	return lhs.Equal(&rhs)
}
