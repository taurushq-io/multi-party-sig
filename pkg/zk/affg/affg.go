package zkaffg

import (
	"crypto/rand"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
)

type Public struct {
	// C is a ciphertext encrypted with N₀
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

type Private struct {
	// X ∈ ± 2ˡ
	// Bob's multiplicative share
	X *safenum.Int

	// Y ∈ ± 2ˡº
	// Bob's additive share βᵢⱼ
	Y *safenum.Int

	// Rho = ρ
	// Nonce D = sᵢⱼ
	Rho *safenum.Nat

	// RhoY = ρy
	// Nonce for Y = rᵢⱼ
	RhoY *safenum.Nat
}
type Commitment struct {
	// A = (α ⊙ c ) ⊕ Enc(N0, beta, r)
	A *paillier.Ciphertext
	// Bₓ = α⋅G
	Bx *curve.Point
	// By = Enc(N1, beta, ry)
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
	*Commitment
	// Z1 = Z₁ = α + e⋅x
	Z1 *safenum.Int
	// Z2 = Z₂ = β + e⋅y
	Z2 *safenum.Int
	// Z3 = Z₃ = γ + e⋅m
	Z3 *safenum.Int
	// Z4 = Z₄ = δ + e⋅μ
	Z4 *safenum.Int
	// W = w = r⋅ρᵉ (mod N₀)
	W *safenum.Nat
	// Wy = wy = ry ⋅ρyᵉ (mod N₁)
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

func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	N0 := public.Verifier.N()
	N1 := public.Prover.N()
	N0CRT := public.Verifier.CRT()
	N1CRT := public.Prover.CRT()

	verifier := public.Verifier
	prover := public.Prover

	alpha := sample.IntervalLEps(rand.Reader)
	beta := sample.IntervalLPrimeEps(rand.Reader)

	r := sample.UnitModN(rand.Reader, N0)
	rY := sample.UnitModN(rand.Reader, N1)

	gamma := sample.IntervalLEpsN(rand.Reader)
	m := sample.IntervalLN(rand.Reader)
	delta := sample.IntervalLEpsN(rand.Reader)
	mu := sample.IntervalLN(rand.Reader)

	cAlpha := public.C.Clone().Mul(verifier, alpha)           // = Cᵃ mod N₀ = α ⊙ C
	A := verifier.EncWithNonce(beta, r).Add(verifier, cAlpha) // = Enc₀(β,r) ⊕ (α ⊙ C)

	E := public.Aux.Commit(alpha, gamma)
	S := public.Aux.Commit(private.X, m)
	F := public.Aux.Commit(beta, delta)
	T := public.Aux.Commit(private.Y, mu)
	commitment := &Commitment{
		A:  A,
		Bx: curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarInt(alpha)),
		By: prover.EncWithNonce(beta, rY),
		E:  E,
		S:  S,
		F:  F,
		T:  T,
	}

	e, _ := challenge(hash, public, commitment)

	// e•x+α
	z1 := new(safenum.Int).Mul(e, private.X, -1)
	z1.Add(z1, alpha, -1)
	// e•y+β
	z2 := new(safenum.Int).Mul(e, private.Y, -1)
	z2.Add(z2, beta, -1)
	// e•m+γ
	z3 := new(safenum.Int).Mul(e, m, -1)
	z3.Add(z3, gamma, -1)
	// e•μ+δ
	z4 := new(safenum.Int).Mul(e, mu, -1)
	z4.Add(z4, delta, -1)
	// (ρᵉ mod N₀)•r mod N₀
	w := N0CRT.ExpI(private.Rho, e)
	w.ModMul(w, r, N0)
	// ( (ρy)ᵉ mod N₁)•ry mod N₁
	wY := N1CRT.ExpI(private.RhoY, e)
	wY.ModMul(wY, rY, N1)

	return &Proof{
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

	e, err := challenge(hash, public, p.Commitment)
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
		lhs := curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarInt(p.Z1))

		// rhsPt = Bₓ + [e]X
		rhs := curve.NewIdentityPoint().ScalarMult(curve.NewScalarInt(e), public.X)
		rhs.Add(p.Bx, rhs)
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

func challenge(hash *hash.Hash, public Public, commitment *Commitment) (e *safenum.Int, err error) {
	err = hash.WriteAny(public.Aux, public.Prover, public.Verifier,
		public.C, public.D, public.Y, public.X,
		commitment.A, commitment.Bx, commitment.By,
		commitment.E, commitment.S, commitment.F, commitment.T)

	e = sample.IntervalScalar(hash.Digest())
	return
}
