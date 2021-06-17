package zklogstar

import (
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
		// C = Enc₀(x;ρ)
		// Encryption of x under the prover's key
		C *paillier.Ciphertext

		// X = [x] G
		// x "in the exponent"
		X *curve.Point

		// G = Base point of the curve,
		// If G = nil, the default base point is used
		G *curve.Point

		Prover *paillier.PublicKey
		Aux    *pedersen.Parameters
	}
	Private struct {
		// X is the plaintext of C and the dlog of X
		X *big.Int

		// Rho = ρ
		// nonce of C
		Rho *big.Int
	}
)

func (p Proof) IsValid(public Public) bool {
	if !public.Prover.ValidateCiphertexts(p.A) {
		return false
	}
	if p.Y.IsIdentity() {
		return false
	}
	if !arith.IsValidModN(public.Prover.N, p.Z2) {
		return false
	}
	return true
}

func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	N := public.Prover.N

	if public.G == nil {
		public.G = curve.NewBasePoint()
	}

	alpha := sample.IntervalLEps()
	r := sample.UnitModN(N)
	mu := sample.IntervalLN()
	gamma := sample.IntervalLEpsN()

	commitment := &Commitment{
		A: public.Prover.EncWithNonce(alpha, r),
		Y: *curve.NewIdentityPoint().ScalarMult(curve.NewScalarBigInt(alpha), public.G),
		S: public.Aux.Commit(private.X, mu),
		D: public.Aux.Commit(alpha, gamma),
	}

	e := challenge(hash, public, commitment)

	var z1, z2, z3 big.Int
	return &Proof{
		Commitment: commitment,
		Z1:         z1.Mul(e, private.X).Add(&z1, alpha),              // z1 = α + e x,
		Z2:         z2.Exp(private.Rho, e, N).Mul(&z2, r).Mod(&z2, N), // z2 = r ρᵉ mod Nₐ,
		Z3:         z3.Mul(e, mu).Add(&z3, gamma),                     // z3 = γ + e μ,
	}
}

func (p Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	if public.G == nil {
		public.G = curve.NewBasePoint()
	}

	if !arith.IsInIntervalLPrimeEps(p.Z1) {
		return false
	}

	prover := public.Prover

	e := challenge(hash, public, p.Commitment)

	if !public.Aux.Verify(p.Z1, p.Z3, p.D, p.S, e) {
		return false
	}

	{
		// lhs = Enc(z₁;z₂)
		lhs := prover.EncWithNonce(p.Z1, p.Z2)

		// rhs = (e ⊙ C) ⊕ A
		rhs := public.C.Clone().Mul(prover, e).Add(prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = [z₁]G
		lhs := curve.NewIdentityPoint().ScalarMult(curve.NewScalarBigInt(p.Z1), public.G)

		// rhs = Y + [e]X
		eX := curve.NewIdentityPoint().ScalarMult(curve.NewScalarBigInt(e), public.X)
		rhs := curve.NewIdentityPoint().Add(&p.Y, eX)

		if !lhs.Equal(rhs) {
			return false
		}

	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment *Commitment) *big.Int {
	_, _ = hash.WriteAny(public.Aux, public.Prover, public.C, public.X, public.G,
		commitment.S, commitment.A, commitment.Y, commitment.D)

	return hash.ReadFqNegative()
}
