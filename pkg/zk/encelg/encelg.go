package zkencelg

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
	// C = Enc(x;ρ)
	C *paillier.Ciphertext

	// A = a⋅G
	A curve.Point
	// B = b⋅G
	B curve.Point
	// X = (ab+x)⋅G
	X curve.Point

	Prover *paillier.PublicKey
	Aux    *pedersen.Parameters
}
type Private struct {
	// X = x = Dec(C)
	X *safenum.Int

	// Rho = ρ = Nonce(C)
	Rho *safenum.Nat

	// A = a
	A curve.Scalar
	// B = b
	B curve.Scalar
}

type Commitment struct {
	// S = sˣtᵘ
	S *safenum.Nat
	// D = Enc(α, r)
	D *paillier.Ciphertext
	// Y = β⋅A+α⋅G
	Y curve.Point
	// Z = β⋅G
	Z curve.Point
	// C = sᵃtᵍ
	T *safenum.Nat
}

type Proof struct {
	group curve.Curve
	*Commitment
	// Z1 = z₁ = α + ex
	Z1 *safenum.Int
	// W = w = β + eb (mod q)
	W curve.Scalar
	// Z2 = z₂ = r⋅ρᵉ (mod N₀)
	Z2 *safenum.Nat
	// Z3 = z₃ = γ + eμ
	Z3 *safenum.Int
}

func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.D) {
		return false
	}
	if p.W.IsZero() || p.Y.IsIdentity() || p.Z.IsIdentity() {
		return false
	}
	if !arith.IsValidNatModN(public.Prover.N(), p.Z2) {
		return false
	}
	return true
}

func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	N := public.Prover.N()
	NModulus := public.Prover.Modulus()

	alpha := sample.IntervalLEps(rand.Reader)
	alphaScalar := group.NewScalar().SetNat(alpha.Mod(group.Order()))
	mu := sample.IntervalLN(rand.Reader)
	r := sample.UnitModN(rand.Reader, N)
	beta := sample.Scalar(rand.Reader, group)
	gamma := sample.IntervalLEpsN(rand.Reader)

	commitment := &Commitment{
		S: public.Aux.Commit(private.X, mu),
		D: public.Prover.EncWithNonce(alpha, r),
		Y: beta.Act(public.A).Add(alphaScalar.ActOnBase()),
		Z: beta.ActOnBase(),
		T: public.Aux.Commit(alpha, gamma),
	}

	e, _ := challenge(hash, group, public, commitment)

	z1 := new(safenum.Int).SetInt(private.X)
	z1.Mul(e, z1, -1)
	z1.Add(z1, alpha, -1)

	w := group.NewScalar().SetNat(e.Mod(group.Order())).Mul(private.B).Add(beta)

	z2 := NModulus.ExpI(private.Rho, e)
	z2.ModMul(z2, r, N)

	z3 := new(safenum.Int).Mul(e, mu, -1)
	z3.Add(z3, gamma, -1)

	return &Proof{
		group:      group,
		Commitment: commitment,
		Z1:         z1,
		W:          w,
		Z2:         z2,
		Z3:         z3,
	}
}

func (p Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	prover := public.Prover

	if !arith.IsInIntervalLEps(p.Z1) {
		return false
	}

	e, err := challenge(hash, p.group, public, p.Commitment)
	if err != nil {
		return false
	}

	group := p.group
	q := group.Order()
	eScalar := group.NewScalar().SetNat(e.Mod(q))

	{
		lhs := prover.EncWithNonce(p.Z1, p.Z2)                  // lhs = Enc(z₁;z₂)
		rhs := public.C.Clone().Mul(prover, e).Add(prover, p.D) // rhs = (e ⊙ C) ⊕ D
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		z1 := group.NewScalar().SetNat(p.Z1.Mod(q))
		lhs := z1.ActOnBase().Add(p.W.Act(public.A)) // lhs = w⋅A+z₁⋅G
		rhs := eScalar.Act(public.X).Add(p.Y)        // rhs = Y+e⋅X
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		lhs := p.W.ActOnBase()                // lhs = w⋅G
		rhs := eScalar.Act(public.B).Add(p.Z) // rhs = Z+e⋅B
		if !lhs.Equal(rhs) {
			return false
		}
	}

	if !public.Aux.Verify(p.Z1, p.Z3, e, p.T, p.S) {
		return false
	}

	return true
}

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e *safenum.Int, err error) {
	err = hash.WriteAny(public.Aux, public.Prover, public.C, public.A, public.B, public.X,
		commitment.S, commitment.D, commitment.Y, commitment.Z, commitment.T)
	e = sample.IntervalScalar(hash.Digest(), group)
	return
}

func Empty(group curve.Curve) *Proof {
	return &Proof{
		group: group,
		Commitment: &Commitment{
			Y: group.NewPoint(),
			Z: group.NewPoint(),
		},
		W: group.NewScalar(),
	}
}
