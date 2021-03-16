package zklog

import (
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
)

const domain = "CMP-LOG"

type Commitment struct {
	// A = g^alpha
	// B = h^alpha
	A, B *curve.Point
}

type Response struct {
	// Z = alpha + ex
	Z *curve.Scalar
}

type Proof struct {
	*Commitment
	*Response
}

func (commitment *Commitment) Challenge() *curve.Scalar {
	var e big.Int
	h := sha512.New()
	h.Write([]byte(domain))

	// TODO Which parameters should we include?
	// Write public parameters to hash
	h.Write([]byte(""))

	// Write commitments
	h.Write(commitment.A.Bytes())
	h.Write(commitment.B.Bytes())

	out := h.Sum(nil)
	e.SetBytes(out)
	return curve.NewScalarBigInt(&e)
}

// NewProof generates a proof that the
func NewProof(h, X, Y *curve.Point, x *curve.Scalar) *Proof {
	alpha := curve.NewScalarRandom()

	commitment := &Commitment{
		A: new(curve.Point).ScalarBaseMult(alpha),
		B: new(curve.Point).ScalarMult(alpha, h),
	}

	e := commitment.Challenge()

	response := &Response{
		Z: new(curve.Scalar).MultiplyAdd(e, x, alpha),
	}

	return &Proof{
		Commitment: commitment,
		Response:   response,
	}
}

func (proof *Proof) Verify(h, X, Y *curve.Point) bool {
	e := proof.Challenge()

	var lhs, rhs curve.Point
	lhs.ScalarBaseMult(proof.Z)
	rhs.ScalarMult(e, X)
	rhs.Add(&rhs, proof.A)

	if lhs.Equal(&rhs) != 1 {
		fmt.Println("fail g")
		return false
	}

	lhs.ScalarMult(proof.Z, h)
	rhs.ScalarMult(e, Y)
	rhs.Add(&rhs, proof.B)

	if lhs.Equal(&rhs) != 1 {
		fmt.Println("fail h")
		return false
	}

	return true
}
