package affp

import (
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/secp256k1"
)

const domainLog = "CMP-LOG"

type Commitment struct {
	// A = g^alpha
	// B = h^alpha
	A, B *secp256k1.Point
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
	h.Write([]byte(domainLog))

	// TODO Which parameters should we include?
	// Write public parameters to hash
	h.Write([]byte(""))

	// Write commitments
	h.Write(commitment.A.Bytes())
	h.Write(commitment.B.Bytes())

	out := h.Sum(nil)
	e.SetBytes(out)
	return secp256k1.NewScalarBigInt(&e)
}

// NewProof generates a proof that the
func NewProof(h, X, Y *secp256k1.Point, x *secp256k1.Scalar) *Proof {
	alpha := secp256k1.NewScalarRandom()

	commitment := &Commitment{
		A: new(secp256k1.Point).ScalarBaseMult(alpha),
		B: new(secp256k1.Point).ScalarMult(alpha, h),
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

func (proof *Proof) Verify(h, X, Y *secp256k1.Point) bool {
	e := proof.Challenge()

	var lhs, rhs secp256k1.Point
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
