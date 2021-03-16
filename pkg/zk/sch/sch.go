package zksch

import (
	"crypto/sha512"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
)

const domain = "CMP-SCH"

type Commitment struct {
	// A = g^alpha
	A *curve.Point
}

type Response struct {
	// Z = alpha + ex
	Z *curve.Scalar
}

type Proof struct {
	*Commitment
	*Response
}

func NewCommitment() (secret *curve.Scalar, commitment *Commitment) {
	secret = curve.NewScalarRandom()
	commitment = &Commitment{
		A: new(curve.Point).ScalarBaseMult(secret),
	}
	return
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

	out := h.Sum(nil)
	e.SetBytes(out)
	return curve.NewScalarBigInt(&e)
}

// NewProof generates a proof that the
func NewProof(X *curve.Point, x *curve.Scalar) *Proof {
	alpha, commitment := NewCommitment()
	e := commitment.Challenge()

	response := &Response{
		Z: new(curve.Scalar).MultiplyAdd(e, x, alpha),
	}

	return &Proof{
		Commitment: commitment,
		Response:   response,
	}
}

func (proof *Proof) Verify(X *curve.Point) bool {
	e := proof.Challenge()

	var lhs, rhs curve.Point
	lhs.ScalarBaseMult(proof.Z)
	rhs.ScalarMult(e, X)
	rhs.Add(&rhs, proof.A)

	return lhs.Equal(&rhs) == 1
}
