package affp

import (
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/secp256k1"
)

const domainELog = "CMP-ELOG"

type Commitment struct {
	// A = g^alpha
	// N = g^m X^alpha
	// B = h^m
	A, N, B *secp256k1.Point
}

type Response struct {
	// Z = alpha + e lambda
	// U = m + ey
	Z, U *secp256k1.Scalar
}

type Proof struct {
	*Commitment
	*Response
}

func (commitment *Commitment) Challenge() *secp256k1.Scalar {
	var e big.Int
	h := sha512.New()
	h.Write([]byte(domainELog))

	// TODO Which parameters should we include?
	// Write public parameters to hash
	h.Write([]byte(""))

	// Write commitments
	h.Write(commitment.A.Bytes())
	h.Write(commitment.N.Bytes())
	h.Write(commitment.B.Bytes())

	out := h.Sum(nil)
	e.SetBytes(out)
	return secp256k1.NewScalarBigInt(&e)
}

// NewProof generates a proof that the
func NewProof(h, X, L, M, Y *secp256k1.Point, lambda, y *secp256k1.Scalar) *Proof {
	alpha := secp256k1.NewScalarRandom()
	m := secp256k1.NewScalarRandom()

	gm := new(secp256k1.Point).ScalarBaseMult(m)
	N := new(secp256k1.Point).ScalarMult(alpha, X)
	N.Add(N, gm)

	commitment := &Commitment{
		A: new(secp256k1.Point).ScalarBaseMult(alpha),
		N: N,
		B: new(secp256k1.Point).ScalarMult(m, h),
	}

	e := commitment.Challenge()

	response := &Response{
		Z: new(secp256k1.Scalar).MultiplyAdd(e, lambda, alpha),
		U: new(secp256k1.Scalar).MultiplyAdd(e, y, m),
	}

	return &Proof{
		Commitment: commitment,
		Response:   response,
	}
}

func (proof *Proof) Verify(h, X, L, M, Y *secp256k1.Point) bool {
	e := proof.Challenge()

	var lhs, rhs secp256k1.Point
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
