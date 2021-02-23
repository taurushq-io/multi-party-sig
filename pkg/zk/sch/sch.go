package affp

import (
	"crypto/sha512"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/secp256k1"
)

const domainSch = "CMP-SCH"

type Commitment struct {
	// A = g^alpha
	A *secp256k1.Point
}

type Response struct {
	// Z = alpha + ex
	Z *secp256k1.Scalar
}

type Proof struct {
	*Commitment
	*Response
}

func (commitment *Commitment) Challenge() *secp256k1.Scalar {
	var e big.Int
	h := sha512.New()
	h.Write([]byte(domainSch))

	// TODO Which parameters should we include?
	// Write public parameters to hash
	h.Write([]byte(""))

	// Write commitments
	h.Write(commitment.A.Bytes())

	out := h.Sum(nil)
	e.SetBytes(out)
	return secp256k1.NewScalarBigInt(&e)
}

// NewProof generates a proof that the
func NewProof(X *secp256k1.Point, x *secp256k1.Scalar) *Proof {
	alpha := secp256k1.NewScalarRandom()

	commitment := &Commitment{
		A: new(secp256k1.Point).ScalarBaseMult(alpha),
	}

	e := commitment.Challenge()

	response := &Response{
		Z: new(secp256k1.Scalar).MultiplyAdd(e, x, alpha),
	}

	return &Proof{
		Commitment: commitment,
		Response:   response,
	}
}

func (proof *Proof) Verify(X *secp256k1.Point) bool {
	e := proof.Challenge()

	var lhs, rhs secp256k1.Point
	lhs.ScalarBaseMult(proof.Z)
	rhs.ScalarMult(e, X)
	rhs.Add(&rhs, proof.A)

	return lhs.Equal(&rhs) == 1
}
