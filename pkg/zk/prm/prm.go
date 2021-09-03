package zkprm

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

type Public struct {
	N    *safenum.Modulus
	S, T *safenum.Nat
}
type Private struct {
	Lambda, Phi, P, Q *safenum.Nat
}

type Proof struct {
	As, Zs [params.StatParam]*big.Int
}

func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}
	if !arith.IsValidBigModN(public.N.Big(), append(p.As[:], p.Zs[:]...)...) {
		return false
	}
	return true
}

// NewProof generates a proof that:
// s = t^lambda (mod N).
func NewProof(private Private, hash *hash.Hash, public Public, pl *pool.Pool) *Proof {
	lambda := private.Lambda
	phi := safenum.ModulusFromNat(private.Phi)

	n := arith.ModulusFromFactors(private.P, private.Q)

	var (
		as [params.StatParam]*safenum.Nat
		As [params.StatParam]*big.Int
	)
	lockedRand := pool.NewLockedReader(rand.Reader)
	pl.Parallelize(params.StatParam, func(i int) interface{} {
		// aᵢ ∈ mod ϕ(N)
		as[i] = sample.ModN(lockedRand, phi)

		// Aᵢ = tᵃ mod N
		As[i] = n.Exp(public.T, as[i]).Big()

		return nil
	})

	es, _ := challenge(hash, public, As)
	// Modular addition is not expensive enough to warrant parallelizing
	var Zs [params.StatParam]*big.Int
	for i := 0; i < params.StatParam; i++ {
		z := as[i]
		// The challenge is public, so branching is ok
		if es[i] {
			z.ModAdd(z, lambda, phi)
		}
		Zs[i] = z.Big()
	}

	return &Proof{
		As: As,
		Zs: Zs,
	}
}

func (p *Proof) Verify(public Public, hash *hash.Hash, pl *pool.Pool) bool {
	if p == nil {
		return false
	}
	if err := pedersen.ValidateParameters(public.N, public.S, public.T); err != nil {
		return false
	}

	n, s, t := public.N.Big(), public.S.Big(), public.T.Big()

	es, err := challenge(hash, public, p.As)
	if err != nil {
		return false
	}

	one := big.NewInt(1)
	verifications := pl.Parallelize(params.StatParam, func(i int) interface{} {
		var lhs, rhs big.Int
		z := p.Zs[i]
		a := p.As[i]

		if !arith.IsValidBigModN(n, a, z) {
			return false
		}

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

		return true
	})
	for i := 0; i < len(verifications); i++ {
		ok, _ := verifications[i].(bool)
		if !ok {
			return false
		}
	}
	return true
}

func challenge(hash *hash.Hash, public Public, A [params.StatParam]*big.Int) (es []bool, err error) {
	err = hash.WriteAny(public.N, public.S, public.T)
	for _, a := range A {
		_ = hash.WriteAny(a)
	}

	tmpBytes := make([]byte, params.StatParam)
	_, _ = io.ReadFull(hash.Digest(), tmpBytes)

	es = make([]bool, params.StatParam)
	for i := range es {
		b := (tmpBytes[i] & 1) == 1
		es[i] = b
	}

	return
}
