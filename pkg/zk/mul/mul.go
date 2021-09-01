package zkmul

import (
	"crypto/rand"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
)

type Public struct {
	// X = Enc(x; ρₓ)
	X *paillier.Ciphertext

	// Y is a ciphertext over the prover's public key
	Y *paillier.Ciphertext

	// C = x ⊙ Y % ρ
	C *paillier.Ciphertext

	// Prover = N
	Prover *paillier.PublicKey
}

type Private struct {
	// X = x is the plaintext of Public.X.
	X *safenum.Int

	// Rho = ρ is the nonce for Public.C.
	Rho *safenum.Nat

	// RhoX = ρₓ is the nonce for Public.X
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

func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	N := public.Prover.N()
	NModulus := public.Prover.Modulus()

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
	e, _ := challenge(hash, group, public, commitment)

	// Z = α + ex
	z := new(safenum.Int).SetInt(private.X)
	z.Mul(e, z, -1)
	z.Add(z, alpha, -1)
	// U = r⋅ρᵉ mod N
	u := NModulus.ExpI(private.Rho, e)
	u.ModMul(u, r, N)
	// V = s⋅ρₓᵉ mod N
	v := NModulus.ExpI(private.RhoX, e)
	v.ModMul(v, s, N)

	return &Proof{
		Commitment: commitment,
		Z:          z,
		U:          u,
		V:          v,
	}
}

func (p *Proof) Verify(group curve.Curve, hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	prover := public.Prover

	e, err := challenge(hash, group, public, p.Commitment)
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

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e *safenum.Int, err error) {
	err = hash.WriteAny(public.Prover,
		public.X, public.Y, public.C,
		commitment.A, commitment.B)
	e = sample.IntervalScalar(hash.Digest(), group)
	return
}
