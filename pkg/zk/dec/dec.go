package zkdec

import (
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

type (
	Public struct {
		// C = Enc₀(y;ρ)
		C *paillier.Ciphertext

		// X = y (mod q)
		X *curve.Scalar

		// Prover = N₀
		Prover *paillier.PublicKey
		Aux    *pedersen.Parameters
	}
	Private struct {
		// Y = y
		Y *big.Int

		// Rho = ρ
		Rho *big.Int
	}
)

func (p Proof) IsValid(public Public) bool {
	if p.Gamma == nil || p.Gamma.IsZero() {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.A) {
		return false
	}
	if !arith.IsValidModN(public.Prover.N, p.W) {
		return false
	}
	return true
}

func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	N0 := public.Prover.N

	alpha := sample.IntervalLEps(rand.Reader)

	mu := sample.IntervalLN(rand.Reader)
	nu := sample.IntervalLEpsN(rand.Reader)
	r := sample.UnitModN(rand.Reader, N0)

	gamma := curve.NewScalarBigInt(alpha)

	commitment := &Commitment{
		S:     public.Aux.Commit(private.Y, mu),
		T:     public.Aux.Commit(alpha, nu),
		A:     public.Prover.EncWithNonce(alpha, r),
		Gamma: gamma,
	}

	e := challenge(hash, public, commitment)

	var z1, z2, w big.Int
	return &Proof{
		Commitment: commitment,
		Z1:         z1.Mul(e, private.Y).Add(&z1, alpha),             // z₁ = e•y+α
		Z2:         z2.Mul(e, mu).Add(&z2, nu),                       // z₂ = e•μ + ν
		W:          w.Exp(private.Rho, e, N0).Mul(&w, r).Mod(&w, N0), // w = ρ^e•r mod N₀
	}
}

func (p *Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	e := challenge(hash, public, p.Commitment)

	if !public.Aux.Verify(p.Z1, p.Z2, p.T, p.S, e) {
		return false
	}

	{
		// lhs = Enc₀(z₁;w)
		lhs := public.Prover.EncWithNonce(p.Z1, p.W)

		// rhs = (e ⊙ C) ⊕ A
		rhs := public.C.Clone().Mul(public.Prover, e).Add(public.Prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = z₁ mod q
		lhs := curve.NewScalarBigInt(p.Z1)

		// rhs = e•x + γ
		rhs := curve.NewScalarBigInt(e)
		rhs.MultiplyAdd(rhs, public.X, p.Gamma)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment *Commitment) *big.Int {
	_, _ = hash.WriteAny(public.Aux, public.Prover,
		public.C, public.X,
		commitment.S, commitment.T, commitment.A, commitment.Gamma)

	return hash.ReadFqNegative()
}
