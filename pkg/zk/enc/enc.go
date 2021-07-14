package zkenc

import (
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

type (
	Public struct {
		// K = Enc₀(k;ρ)
		K *paillier.Ciphertext

		Prover *paillier.PublicKey
		Aux    *pedersen.Parameters
	}
	Private struct {
		// K = k ∈ 2ˡ = Dec₀(K)
		// plaintext of K
		K *big.Int

		// Rho = ρ
		// nonce of K
		Rho *big.Int
	}
)

func (p Proof) IsValid(public Public) bool {
	if !public.Prover.ValidateCiphertexts(p.A) {
		return false
	}
	if !arith.IsValidModN(public.Prover.N, p.Z2) {
		return false
	}
	return true
}

func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	N := public.Prover.N

	alpha := sample.IntervalLEps(rand.Reader)
	r := sample.UnitModN(rand.Reader, N)
	mu := sample.IntervalLN(rand.Reader)
	gamma := sample.IntervalLEpsN(rand.Reader)

	A := public.Prover.EncWithNonce(alpha, r)

	commitment := &Commitment{
		S: public.Aux.Commit(private.K, mu),
		A: A,
		C: public.Aux.Commit(alpha, gamma),
	}

	e := challenge(hash, public, commitment)

	var z1, z2, z3 big.Int
	return &Proof{
		Commitment: commitment,
		Z1:         z1.Mul(e, private.K).Add(&z1, alpha),
		Z2:         z2.Exp(private.Rho, e, N).Mul(&z2, r).Mod(&z2, N),
		Z3:         z3.Mul(e, mu).Add(&z3, gamma),
	}
}

func (p Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	prover := public.Prover

	if !arith.IsInIntervalLPrimeEps(p.Z1) {
		return false
	}

	e := challenge(hash, public, p.Commitment)

	if !public.Aux.Verify(p.Z1, p.Z3, p.C, p.S, e) {
		return false
	}

	{
		// lhs = Enc(z₁;z₂)
		lhs := prover.EncWithNonce(p.Z1, p.Z2)

		// rhs = (e ⊙ K) ⊕ A
		rhs := public.K.Clone().Mul(prover, e).Add(prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment *Commitment) *big.Int {
	_, _ = hash.WriteAny(public.Aux, public.Prover, public.K,
		commitment.S, commitment.A, commitment.C)

	return sample.IntervalScalar(hash)
}
