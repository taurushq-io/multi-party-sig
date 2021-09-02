package zkaffg

import (
	"crypto/rand"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
)

type Public struct {
	// Kv is a ciphertext encrypted with Nᵥ
	// Original name: C
	Kv *paillier.Ciphertext

	// Dv = (x ⨀ Kv) ⨁ Encᵥ(y;s)
	Dv *paillier.Ciphertext

	// Fp = Encₚ(y;r)
	// Original name: Y
	Fp *paillier.Ciphertext

	// Xp = gˣ
	Xp curve.Point

	// Prover = Nₚ
	// Verifier = Nᵥ
	Prover, Verifier *paillier.PublicKey
	Aux              *pedersen.Parameters
}

type Private struct {
	// X = x
	X *safenum.Int
	// Y = y
	Y *safenum.Int
	// S = s
	// Original name: ρ
	S *safenum.Nat
	// R = r
	// Original name: ρy
	R *safenum.Nat
}
type Commitment struct {
	// A = (α ⊙ C) ⊕ Encᵥ(β, ρ)
	A *paillier.Ciphertext
	// Bₓ = α⋅G
	Bx curve.Point
	// By = Encₚ(β, ρy)
	By *paillier.Ciphertext
	// E = sᵃ tᵍ (mod N)
	E *safenum.Nat
	// S = sˣ tᵐ (mod N)
	S *safenum.Nat
	// F = sᵇ tᵈ (mod N)
	F *safenum.Nat
	// T = sʸ tᵘ (mod N)
	T *safenum.Nat
}

type Proof struct {
	group curve.Curve
	*Commitment
	// Z1 = Z₁ = α + e⋅x
	Z1 *safenum.Int
	// Z2 = Z₂ = β + e⋅y
	Z2 *safenum.Int
	// Z3 = Z₃ = γ + e⋅m
	Z3 *safenum.Int
	// Z4 = Z₄ = δ + e⋅μ
	Z4 *safenum.Int
	// W = w = ρ⋅sᵉ (mod N₀)
	W *safenum.Nat
	// Wy = wy = ρy⋅rᵉ (mod N₁)
	Wy *safenum.Nat
}

func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}
	if !public.Verifier.ValidateCiphertexts(p.A) {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.By) {
		return false
	}
	if !arith.IsValidNatModN(public.Prover.N(), p.Wy) {
		return false
	}
	if !arith.IsValidNatModN(public.Verifier.N(), p.W) {
		return false
	}
	if p.Bx.IsIdentity() {
		return false
	}
	return true
}

func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	N0 := public.Verifier.N()
	N1 := public.Prover.N()
	N0Modulus := public.Verifier.Modulus()
	N1Modulus := public.Prover.Modulus()

	verifier := public.Verifier
	prover := public.Prover

	alpha := sample.IntervalLEps(rand.Reader)
	beta := sample.IntervalLPrimeEps(rand.Reader)

	rho := sample.UnitModN(rand.Reader, N0)
	rhoY := sample.UnitModN(rand.Reader, N1)

	gamma := sample.IntervalLEpsN(rand.Reader)
	m := sample.IntervalLN(rand.Reader)
	delta := sample.IntervalLEpsN(rand.Reader)
	mu := sample.IntervalLN(rand.Reader)

	cAlpha := public.Kv.Clone().Mul(verifier, alpha)            // = Cᵃ mod N₀ = α ⊙ Kv
	A := verifier.EncWithNonce(beta, rho).Add(verifier, cAlpha) // = Enc₀(β,ρ) ⊕ (α ⊙ Kv)

	E := public.Aux.Commit(alpha, gamma)
	S := public.Aux.Commit(private.X, m)
	F := public.Aux.Commit(beta, delta)
	T := public.Aux.Commit(private.Y, mu)
	commitment := &Commitment{
		A:  A,
		Bx: group.NewScalar().SetNat(alpha.Mod(group.Order())).ActOnBase(),
		By: prover.EncWithNonce(beta, rhoY),
		E:  E,
		S:  S,
		F:  F,
		T:  T,
	}

	e, _ := challenge(hash, group, public, commitment)

	// e•x+α
	z1 := new(safenum.Int).SetInt(private.X)
	z1.Mul(e, z1, -1)
	z1.Add(z1, alpha, -1)
	// e•y+β
	z2 := new(safenum.Int).SetInt(private.Y)
	z2.Mul(e, z2, -1)
	z2.Add(z2, beta, -1)
	// e•m+γ
	z3 := new(safenum.Int).Mul(e, m, -1)
	z3.Add(z3, gamma, -1)
	// e•μ+δ
	z4 := new(safenum.Int).Mul(e, mu, -1)
	z4.Add(z4, delta, -1)
	// ρ⋅sᵉ mod N₀
	w := N0Modulus.ExpI(private.S, e)
	w.ModMul(w, rho, N0)
	// ρy⋅rᵉ  mod N₁
	wY := N1Modulus.ExpI(private.R, e)
	wY.ModMul(wY, rhoY, N1)

	return &Proof{
		group:      group,
		Commitment: commitment,
		Z1:         z1,
		Z2:         z2,
		Z3:         z3,
		Z4:         z4,
		W:          w,
		Wy:         wY,
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

	e, err := challenge(hash, p.group, public, p.Commitment)
	if err != nil {
		return false
	}

	if !public.Aux.Verify(p.Z1, p.Z3, e, p.E, p.S) {
		return false
	}

	if !public.Aux.Verify(p.Z2, p.Z4, e, p.F, p.T) {
		return false
	}

	{
		// tmp = z₁ ⊙ Kv
		// lhs = Enc₀(z₂;w) ⊕ z₁ ⊙ Kv
		tmp := public.Kv.Clone().Mul(verifier, p.Z1)
		lhs := verifier.EncWithNonce(p.Z2, p.W).Add(verifier, tmp)

		// rhs = (e ⊙ Dv) ⊕ A
		rhs := public.Dv.Clone().Mul(verifier, e).Add(verifier, p.A)

		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = [z₁]G
		lhs := p.group.NewScalar().SetNat(p.Z1.Mod(p.group.Order())).ActOnBase()

		// rhsPt = Bₓ + [e]Xp
		rhs := p.group.NewScalar().SetNat(e.Mod(p.group.Order())).Act(public.Xp)
		rhs = rhs.Add(p.Bx)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = Enc₁(z₂; wy)
		lhs := prover.EncWithNonce(p.Z2, p.Wy)

		// rhs = (e ⊙ Fp) ⊕ By
		rhs := public.Fp.Clone().Mul(prover, e).Add(prover, p.By)

		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e *safenum.Int, err error) {
	err = hash.WriteAny(public.Aux, public.Prover, public.Verifier,
		public.Kv, public.Dv, public.Fp, public.Xp,
		commitment.A, commitment.Bx, commitment.By,
		commitment.E, commitment.S, commitment.F, commitment.T)

	e = sample.IntervalScalar(hash.Digest(), group)
	return
}

func Empty(group curve.Curve) *Proof {
	return &Proof{
		group:      group,
		Commitment: &Commitment{Bx: group.NewPoint()},
	}
}
