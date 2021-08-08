package zkmulstar

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
type Private struct {
	// X ∈ ± 2ˡ
	X *safenum.Int

	// Rho = ρ = Nonce D
	Rho *safenum.Nat
}

type Commitment struct {
	// A = (α ⊙ c) ⊕ Enc(N₀, β, r)
	A *paillier.Ciphertext
	// Bₓ = gᵃ
	Bx *curve.Point
	// E = sᵃ tᵍ
	E *safenum.Nat
	// S = sˣ tᵐ
	S *safenum.Nat
}
type Proof struct {
	*Commitment
	// Z1 = α + ex
	Z1 *safenum.Int
	// Z2 = y + em
	Z2 *safenum.Int
	// W = ρᵉ•r mod N₀
	W *safenum.Nat
}

func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}
	if !arith.IsValidNatModN(public.Verifier.N(), p.W) {
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
	N0 := public.Verifier.N()

	verifier := public.Verifier

	alpha := sample.IntervalLEps(rand.Reader)

	r := sample.UnitModN(rand.Reader, N0)

	gamma := sample.IntervalLEpsN(rand.Reader)
	m := sample.IntervalLEpsN(rand.Reader)

	A := public.C.Clone().Mul(verifier, alpha)
	A.Randomize(verifier, r)

	commitment := &Commitment{
		A:  A,
		Bx: curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarInt(alpha)),
		E:  public.Aux.Commit(alpha, gamma),
		S:  public.Aux.Commit(private.X, m),
	}

	e, _ := challenge(hash, public, commitment)

	// z₁ = e•x+α
	z1 := new(safenum.Int).Mul(e, private.X, -1)
	z1.Add(z1, alpha, -1)
	// z₂ = e•m+γ
	z2 := new(safenum.Int).Mul(e, m, -1)
	z2.Add(z2, gamma, -1)
	// w = ρᵉ•r mod N₀
	w := new(safenum.Nat).ExpI(private.Rho, e, N0)
	w.ModMul(w, r, N0)

	return &Proof{
		Commitment: commitment,
		Z1:         z1,
		Z2:         z2,
		W:          w,
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

	e, err := challenge(hash, public, p.Commitment)
	if err != nil {
		return false
	}

	if !public.Aux.Verify(p.Z1, p.Z2, e, p.E, p.S) {
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
		lhs := curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarInt(p.Z1))

		// rhs = [e]X + Bₓ
		rhs := curve.NewIdentityPoint().ScalarMult(curve.NewScalarInt(e), public.X)
		rhs.Add(rhs, p.Bx)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment *Commitment) (e *safenum.Int, err error) {
	err = hash.WriteAny(public.Aux, public.Verifier,
		public.C, public.D, public.X,
		commitment.A, commitment.Bx,
		commitment.E, commitment.S)
	e = sample.IntervalScalar(hash.Digest())
	return
}
