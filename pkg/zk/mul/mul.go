package zkmul

import (
	"crypto/rand"
	"math/big"

	"github.com/cronokirby/safenum"
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
	if !arith.IsValidModN(public.Prover.N(), p.U, p.V) {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.A, p.B) {
		return false
	}
	return true
}

func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	NBig := public.Prover.N()
	N := safenum.ModulusFromNat(new(safenum.Nat).SetBig(NBig, NBig.BitLen()))
	xSafe := new(safenum.Int).SetBig(private.X, private.X.BitLen())
	rhoSafe := new(safenum.Nat).SetBig(private.Rho, private.Rho.BitLen())
	rhoXSafe := new(safenum.Nat).SetBig(private.RhoX, private.RhoX.BitLen())

	prover := public.Prover

	alpha := sample.IntervalLEps(rand.Reader)
	alphaSafe := new(safenum.Int).SetBig(alpha, alpha.BitLen())
	r := sample.UnitModNNat(rand.Reader, N)
	s := sample.UnitModNNat(rand.Reader, N)

	A := public.Y.Clone().Mul(prover, alpha)
	A.Randomize(prover, r.Big())

	commitment := &Commitment{
		A: A,
		B: prover.EncWithNonce(alpha, s.Big()),
	}
	eBig := challenge(hash, public, commitment)
	e := new(safenum.Int).SetBig(eBig, eBig.BitLen())

	// Z = α + ex
	z := new(safenum.Int).Mul(e, xSafe, -1)
	z.Add(z, alphaSafe, -1)
	// U = r⋅ρᵉ mod N
	u := new(safenum.Nat).ExpI(rhoSafe, e, N)
	u.ModMul(u, r, N)
	// V = s⋅ρₓᵉ
	v := new(safenum.Nat).ExpI(rhoXSafe, e, N)
	v.ModMul(v, s, N)

	return &Proof{
		Commitment: commitment,
		Z:          z.Big(),
		U:          u.Big(),
		V:          v.Big(),
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
