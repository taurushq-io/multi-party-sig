package zkmul

import (
	"crypto/rand"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
)

type Public struct {
	// X = Enc(x; ρₓ)
	X *paillier.Ciphertext

	// Y = Enc(?;?)
	Y *paillier.Ciphertext

	// C = x ⊙ Y % ρ
	C *paillier.Ciphertext

	// Prover = N
	Prover *paillier.PublicKey
}
type Private struct {
	// X enc of X
	X *safenum.Int

	// Rho = Nonce C = ρ
	Rho *safenum.Nat

	// RhoX = Nonce X = ρₓ
	RhoX *safenum.Nat
}
type Commitment struct {
	// A = α ⊙ Y % ρ
	A *paillier.Ciphertext
	// B = Enc(α;s)
	B *paillier.Ciphertext
}

type Proof struct {
	*Commitment
	// Z = α + ex
	Z *safenum.Int
	// U = r⋅ρᵉ mod N
	U *safenum.Nat
	// V = s⋅ρₓᵉ
	V *safenum.Nat
}

func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}
	if !arith.IsValidNatModN(public.Prover.N(), p.U, p.V) {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.A, p.B) {
		return false
	}
	return true
}

func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	N := public.Prover.N()

	prover := public.Prover

	alpha := sample.IntervalLEps(rand.Reader)
	r := sample.UnitModN(rand.Reader, N)
	s := sample.UnitModN(rand.Reader, N)

	A := public.Y.Clone().Mul(prover, alpha)
	A.Randomize(prover, r)

	commitment := &Commitment{
		A: A,
		B: prover.EncWithNonce(alpha, s),
	}
	e, _ := challenge(hash, public, commitment)

	// Z = α + ex
	z := new(safenum.Int).Mul(e, private.X, -1)
	z.Add(z, alpha, -1)
	// U = r⋅ρᵉ mod N
	u := new(safenum.Nat).ExpI(private.Rho, e, N)
	u.ModMul(u, r, N)
	// V = s⋅ρₓᵉ
	v := new(safenum.Nat).ExpI(private.RhoX, e, N)
	v.ModMul(v, s, N)

	return &Proof{
		Commitment: commitment,
		Z:          z,
		U:          u,
		V:          v,
	}
}

func (p *Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	prover := public.Prover

	e, err := challenge(hash, public, p.Commitment)
	if err != nil {
		return false
	}

	{
		// lhs = (z ⊙ Y)•uᴺ
		lhs := public.Y.Clone().Mul(prover, p.Z)
		lhs.Randomize(prover, p.U)

		// (e ⊙ C) ⊕ A
		rhs := public.C.Clone().Mul(prover, e).Add(prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = Enc(z;v)
		lhs := prover.EncWithNonce(p.Z, p.V)

		// rhs = (e ⊙ X) ⊕ B
		rhs := public.X.Clone().Mul(prover, e).Add(prover, p.B)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment *Commitment) (e *safenum.Int, err error) {
	err = hash.WriteAny(public.Prover,
		public.X, public.Y, public.C,
		commitment.A, commitment.B)
	e = sample.IntervalScalar(hash.Digest())
	return
}
