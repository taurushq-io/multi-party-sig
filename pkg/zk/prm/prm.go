package zkprm

import (
	"crypto/sha256"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/pedersen"
)

var four = big.NewInt(4)

const domain = "CMP-PRM"

type Commitment struct {
	A [params.StatParam]big.Int
}

type Response struct {
	Z [params.StatParam]big.Int
}

type Proof struct {
	*Commitment
	*Response
}

func (commitment *Commitment) Challenge() [params.StatParam]bool {
	h := sha256.New()
	var challenges [params.StatParam]bool
	buffer := make([]byte, params.PaillierBits/8)
	for i := 0; i < params.StatParam; i++ {
		commitment.A[i].FillBytes(buffer)
		h.Write(buffer)
	}
	out := h.Sum(nil)
	for i := 0; i < params.StatParam; i++ {
		curByte := i / 8
		bit := byte(1 << (i % 8))
		challenges[i] = (out[curByte] & bit) == 1
	}
	return challenges
}

// NewProof generates a proof that:
// s = t^lambda (mod N)
func NewProof(v *pedersen.Verifier, lambda, phi *big.Int) *Proof {
	var (
		commitment Commitment
		response   Response
	)

	var a [params.StatParam]*big.Int

	for i := 0; i < params.StatParam; i++ {
		a[i] = sample.PlusMinus(params.L, true)
		commitment.A[i].Exp(v.T, a[i], v.N)
		a[i].Mod(a[i], phi)
	}

	es := commitment.Challenge()
	for i := 0; i < params.StatParam; i++ {
		// TODO make constant time
		if es[i] {
			response.Z[i].Add(a[i], lambda)
		} else {
			response.Z[i].Set(a[i])
		}
		response.Z[i].Mod(&response.Z[i], phi)
	}

	return &Proof{
		Commitment: &commitment,
		Response:   &response,
	}
}

var one = big.NewInt(1)

func (proof *Proof) Verify(v *pedersen.Verifier) bool {
	var gcd big.Int
	if gcd.GCD(nil, nil, v.N, v.S).Cmp(one) != 0 {
		return false
	}
	if gcd.GCD(nil, nil, v.N, v.T).Cmp(one) != 0 {
		return false
	}

	var lhs, rhs big.Int
	es := proof.Challenge()
	for i := 0; i < params.StatParam; i++ {
		lhs.Exp(v.T, &proof.Z[i], v.N)
		if es[i] {
			rhs.Mul(&proof.A[i], v.S)
			rhs.Mod(&rhs, v.N)
			if lhs.Cmp(&rhs) != 0 {
				return false
			}
		} else {
			if lhs.Cmp(&proof.A[i]) != 0 {
				return false
			}
		}
	}
	return true
}
