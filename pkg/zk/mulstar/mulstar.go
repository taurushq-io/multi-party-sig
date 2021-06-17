package zkmulstar

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
		// C = Enc₀(?;?)
		C *paillier.Ciphertext

		// D = (x ⨀ C) ⨁ Enc₀(y;ρ)
		D *paillier.Ciphertext

		// X = gˣ
		X *curve.Point

		// Verifier = N₀
		Verifier *paillier.PublicKey
		Aux      *pedersen.Parameters
	}
	Private struct {
		// X ∈ ± 2ˡ
		X *big.Int

		// Rho = ρ = Nonce D
		Rho *big.Int
	}
)

func (p Proof) IsValid(public Public) bool {
	if !arith.IsValidModN(public.Verifier.N, p.W) {
		return false
	}
	if !public.Verifier.ValidateCiphertexts(p.A) {
		return false
	}
	if p.Bx.IsIdentity() {
		return false
	}
	return true
}

func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	N0 := public.Verifier.N

	verifier := public.Verifier

	alpha := sample.IntervalLEps()

	r := sample.UnitModN(N0)

	gamma := sample.IntervalLEpsN()
	m := sample.IntervalLEpsN()

	A := public.C.Clone().Mul(verifier, alpha)
	A.Randomize(verifier, r)

	commitment := &Commitment{
		A:  A,
		Bx: *curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarBigInt(alpha)),
		E:  public.Aux.Commit(alpha, gamma),
		S:  public.Aux.Commit(private.X, m),
	}

	e := challenge(hash, public, commitment)

	var z1, z2, w big.Int
	return &Proof{
		Commitment: commitment,
		Z1:         z1.Mul(e, private.X).Add(&z1, alpha),             // z₁ = e•x+α
		Z2:         z2.Mul(e, m).Add(&z2, gamma),                     // z₂ = e•m+γ
		W:          w.Exp(private.Rho, e, N0).Mul(&w, r).Mod(&w, N0), // w = ρ^e•r mod N₀
	}
}

func (p *Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	verifier := public.Verifier

	if !arith.IsInIntervalLEps(p.Z1) {
		return false
	}

	e := challenge(hash, public, p.Commitment)

	if !public.Aux.Verify(p.Z1, p.Z2, p.E, p.S, e) {
		return false
	}

	{
		// lhs = z₁ ⊙ C + rand
		lhs := public.C.Clone().Mul(verifier, p.Z1)
		lhs.Randomize(verifier, p.W)

		// rhsCt = A ⊕ (e ⊙ D)
		rhs := public.D.Clone().Mul(verifier, e).Add(verifier, p.A)

		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = [z₁]G
		lhs := curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarBigInt(p.Z1))

		// rhs = [e]X + Bₓ
		rhs := curve.NewIdentityPoint().ScalarMult(curve.NewScalarBigInt(e), public.X)
		rhs.Add(rhs, &p.Bx)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment *Commitment) *big.Int {
	_, _ = hash.WriteAny(public.Aux, public.Verifier,
		public.C, public.D, public.X,
		commitment.A, commitment.Bx,
		commitment.E, commitment.S)

	return hash.ReadFqNegative()
}
