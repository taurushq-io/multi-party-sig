package zkaffg

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
		// Kⱼ = Encⱼ(kⱼ; )
		C *paillier.Ciphertext

		// D = (x ⨀ C) ⨁ Enc₀(y;ρ)
		//   = (xᵢ ⨀ Kⱼ) ⨁ Encⱼ(- βᵢⱼ; sᵢⱼ)
		D *paillier.Ciphertext

		// Y = Enc₁(y;ρ')
		//   = Encᵢ(βᵢⱼ,rᵢⱼ)
		// y is Bob's additive share
		Y *paillier.Ciphertext

		// X = gˣ
		// x is Alice's multiplicative share
		X *curve.Point

		// Prover = N₁
		// Verifier = N₀
		Prover, Verifier *paillier.PublicKey
		Aux              *pedersen.Parameters
	}

	Private struct {
		// X ∈ ± 2ˡ
		// Bob's multiplicative share
		X *big.Int

		// Y ∈ ± 2ˡº
		// Bob's additive share βᵢⱼ
		Y *big.Int

		// Rho = Nonce D = sᵢⱼ
		Rho *big.Int

		// RhoY = Nonce Y = rᵢⱼ
		RhoY *big.Int
	}
)

func (p Proof) IsValid(public Public) bool {
	if !public.Verifier.ValidateCiphertexts(p.A) {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.By) {
		return false
	}
	if !arith.IsValidModN(public.Prover.N, p.Wy) {
		return false
	}
	if !arith.IsValidModN(public.Verifier.N, p.W) {
		return false
	}
	if p.Bx.IsIdentity() {
		return false
	}
	return true
}

func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	N0 := public.Verifier.N
	N1 := public.Prover.N

	verifier := public.Verifier
	prover := public.Prover

	alpha := sample.IntervalLEps()
	beta := sample.IntervalLPrimeEps()

	r := sample.UnitModN(N0)
	rY := sample.UnitModN(N1)

	gamma := sample.IntervalLEpsN()
	m := sample.IntervalLEpsN()
	delta := sample.IntervalLEpsN()
	mu := sample.IntervalLN()

	cAlpha := public.C.Clone().Mul(verifier, alpha)           // = Cᵃ mod N₀ = α ⊙ C
	A := verifier.EncWithNonce(beta, r).Add(verifier, cAlpha) // = Enc₀(β,r) ⊕ (α ⊙ C)

	commitment := &Commitment{
		A:  A,
		Bx: *curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarBigInt(alpha)),
		By: prover.EncWithNonce(beta, rY),
		E:  public.Aux.Commit(alpha, gamma),
		S:  public.Aux.Commit(private.X, m),
		F:  public.Aux.Commit(beta, delta),
		T:  public.Aux.Commit(private.Y, mu),
	}

	e := challenge(hash, public, commitment)

	var z1, z2, z3, z4, w, wy big.Int

	return &Proof{
		Commitment: commitment,
		Z1:         z1.Mul(e, private.X).Add(&z1, alpha),                  // e•x+α
		Z2:         z2.Mul(e, private.Y).Add(&z2, beta),                   // e•y+β
		Z3:         z3.Mul(e, m).Add(&z3, gamma),                          // e•m+γ
		Z4:         z4.Mul(e, mu).Add(&z4, delta),                         // e•μ+δ
		W:          w.Exp(private.Rho, e, N0).Mul(&w, r).Mod(&w, N0),      // (ρᵉ mod N₀)•r mod N₀
		Wy:         wy.Exp(private.RhoY, e, N1).Mul(&wy, rY).Mod(&wy, N1), // ( (ρy)ᵉ mod N₁)•ry mod N₁
	}
}

func (p Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	verifier := public.Verifier
	prover := public.Prover

	if !arith.IsInIntervalLEps(p.Z1) {
		return false
	}
	if !arith.IsInIntervalLPrimeEps(p.Z2) {
		return false
	}

	e := challenge(hash, public, p.Commitment)

	if !public.Aux.Verify(p.Z1, p.Z3, p.E, p.S, e) {
		return false
	}

	if !public.Aux.Verify(p.Z2, p.Z4, p.F, p.T, e) {
		return false
	}

	{
		// tmp = z₁ ⊙ C
		// lhs = Enc₀(z₂;w) ⊕ z₁ ⊙ C
		tmp := public.C.Clone().Mul(verifier, p.Z1)
		lhs := verifier.EncWithNonce(p.Z2, p.W).Add(verifier, tmp)

		// rhs = (e ⊙ D) ⊕ A
		rhs := public.D.Clone().Mul(verifier, e).Add(verifier, p.A)

		if !lhs.Equal(rhs) {
			return false
		}
	}

	{

		// lhs = [z₁]G
		lhs := curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarBigInt(p.Z1))

		// rhsPt = Bₓ + [e]X
		rhs := curve.NewIdentityPoint().ScalarMult(curve.NewScalarBigInt(e), public.X)
		rhs.Add(&p.Bx, rhs)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = Enc₁(z₂; wy)
		lhs := prover.EncWithNonce(p.Z2, p.Wy)

		// rhs = (e ⊙ Y) ⊕ By
		rhs := public.Y.Clone().Mul(prover, e).Add(prover, p.By)

		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment *Commitment) *big.Int {
	_, _ = hash.WriteAny(public.Aux, public.Prover, public.Verifier,
		public.C, public.D, public.Y, public.X,
		commitment.A, commitment.Bx, commitment.By,
		commitment.E, commitment.S, commitment.F, commitment.T)

	return hash.ReadFqNegative()
}
