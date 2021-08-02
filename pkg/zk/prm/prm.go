package zkprm

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/internal/hash"
	"github.com/taurusgroup/cmp-ecdsa/internal/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
)

type (
	Public struct {
		N, S, T *big.Int
	}
	Private struct {
		Lambda, Phi *safenum.Nat
	}
)

func (p Proof) IsValid(public Public) bool {
	if len(*p.A) != params.StatParam || len(*p.Z) != params.StatParam {
		return false
	}
	if !arith.IsValidModN(public.N, *p.A...) {
		return false
	}
	if !arith.IsValidModN(public.N, *p.Z...) {
		return false
	}
	if !arith.IsValidModN(public.N, public.S, public.T) {
		return false
	}
	if public.S.Cmp(public.T) == 0 {
		return false
	}
	return true
}

// NewProof generates a proof that:
// s = t^lambda (mod N).
func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	n := public.N
	lambda := private.Lambda
	phi := safenum.ModulusFromNat(private.Phi)

	a := make([]*safenum.Nat, params.StatParam)
	A := make([]*big.Int, params.StatParam)

	for i := 0; i < params.StatParam; i++ {
		// aᵢ ∈ mod ϕ(N)
		a[i] = sample.ModN(rand.Reader, phi)

		// Aᵢ = tᵃ mod N
		A[i] = a[i].Big()
		A[i] = A[i].Exp(public.T, A[i], n)
	}

	es := challenge(hash, public, A)

	Z := make([]*big.Int, params.StatParam)
	for i := 0; i < params.StatParam; i++ {
		z := a[i]
		// The challenge is public, so branching is ok
		if es[i] {
			z.ModAdd(z, lambda, phi)
		}
		Z[i] = z.Big()
	}

	return &Proof{
		A: &A,
		Z: &Z,
	}
}

func (p *Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	n, s, t := public.N, public.S, public.T

	es := challenge(hash, public, *p.A)

	var lhs, rhs big.Int
	one := big.NewInt(1)
	for i := 0; i < params.StatParam; i++ {
		z := (*p.Z)[i]
		a := (*p.A)[i]

		if a.Cmp(one) == 0 {
			return false
		}

		lhs.Exp(t, z, n)
		if es[i] {
			rhs.Mul(a, s)
			rhs.Mod(&rhs, n)
		} else {
			rhs.Set(a)
		}

		if lhs.Cmp(&rhs) != 0 {
			return false
		}
	}
	return true
}

func challenge(hash *hash.Hash, public Public, A []*big.Int) []bool {
	_ = hash.WriteAny(public.N, public.S, public.T)
	for _, a := range A {
		_ = hash.WriteAny(a)
	}

	tmpBytes := make([]byte, params.StatParam)
	_, _ = io.ReadFull(hash.Digest(), tmpBytes)

	out := make([]bool, params.StatParam)
	for i := range out {
		b := (tmpBytes[i] & 1) == 1
		out[i] = b
	}

	return out
}
