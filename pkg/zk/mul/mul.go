package zkmul

import (
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
)

type (
	Public struct {
		// X = Enc(x; ρₓ)
		X *paillier.Ciphertext

		// Y = Enc(?;?)
		Y *paillier.Ciphertext

		// C = x ⊙ Y % ρ
		C *paillier.Ciphertext

		// Prover = N
		Prover *paillier.PublicKey
	}
	Private struct {
		// X enc of X
		X *big.Int

		// Rho = Nonce C = ρ
		Rho *big.Int

		// RhoX = Nonce X = ρₓ
		RhoX *big.Int
	}
)

func (p *Proof) IsValid(public Public) bool {
	if !arith.IsValidModN(public.Prover.N, p.U, p.V) {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.A, p.B) {
		return false
	}
	return true
}

func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	N := public.Prover.N

	prover := public.Prover

	alpha := sample.UnitModN(rand.Reader, N)
	r := sample.UnitModN(rand.Reader, N)
	s := sample.UnitModN(rand.Reader, N)

	A := public.Y.Clone().Mul(prover, alpha)
	A.Randomize(prover, r)

	commitment := &Commitment{
		A: A,
		B: prover.EncWithNonce(alpha, s),
	}
	e := challenge(hash, public, commitment)

	var z, u, v big.Int
	return &Proof{
		Commitment: commitment,
		Z:          z.Mul(e, private.X).Add(&z, alpha),              // Z = α + ex
		U:          u.Exp(private.Rho, e, N).Mul(&u, r).Mod(&u, N),  // U = r⋅ρᵉ mod N
		V:          v.Exp(private.RhoX, e, N).Mul(&v, s).Mod(&v, N), // V = s⋅ρₓᵉ
	}
}

func (p *Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	prover := public.Prover

	e := challenge(hash, public, p.Commitment)

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

func challenge(hash *hash.Hash, public Public, commitment *Commitment) *big.Int {
	_, _ = hash.WriteAny(public.Prover,
		public.X, public.Y, public.C,
		commitment.A, commitment.B)
	return sample.IntervalScalar(hash)
}
