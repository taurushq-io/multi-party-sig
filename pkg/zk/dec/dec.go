package zkdec

import (
	"crypto/rand"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

type (
	Public struct {
		// C = Enc₀(y;ρ)
		C *paillier.Ciphertext

		// X = y (mod q)
		X *curve.Scalar

		// Prover = N₀
		Prover *paillier.PublicKey
		Aux    *pedersen.Parameters
	}
	Private struct {
		// Y = y
		Y *big.Int

		// Rho = ρ
		Rho *big.Int
	}
)

func (p Proof) IsValid(public Public) bool {
	if p.Gamma == nil || p.Gamma.IsZero() {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.A) {
		return false
	}
	if !arith.IsValidModN(public.Prover.N(), p.W) {
		return false
	}
	return true
}

func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	N0Big := public.Prover.N()
	N0 := safenum.ModulusFromNat(new(safenum.Nat).SetBig(N0Big, N0Big.BitLen()))
	ySafe := new(safenum.Int).SetBig(private.Y, private.Y.BitLen())
	rhoSafe := new(safenum.Nat).SetBig(private.Rho, private.Rho.BitLen())

	alpha := sample.IntervalLEps(rand.Reader)
	alphaSafe := new(safenum.Int).SetBig(alpha, alpha.BitLen())

	mu := sample.IntervalLNSecret(rand.Reader)
	nu := sample.IntervalLEpsNSecret(rand.Reader)
	r := sample.UnitModNNat(rand.Reader, N0)

	gamma := curve.NewScalarBigInt(alpha)

	commitment := &Commitment{
		S:     public.Aux.Commit(ySafe, mu),
		T:     public.Aux.Commit(alphaSafe, nu),
		A:     public.Prover.EncWithNonce(alpha, r.Big()),
		Gamma: gamma,
	}

	eBig := challenge(hash, public, commitment)
	e := new(safenum.Int).SetBig(eBig, eBig.BitLen())

	// z₁ = e•y+α
	z1 := new(safenum.Int).Mul(e, ySafe, -1)
	z1.Add(z1, alphaSafe, -1)
	// z₂ = e•μ + ν
	z2 := new(safenum.Int).Mul(e, mu, -1)
	z2.Add(z2, nu, -1)
	// w = ρ^e•r mod N₀
	w := new(safenum.Nat).ExpI(rhoSafe, e, N0)
	w.ModMul(w, r, N0)

	return &Proof{
		Commitment: commitment,
		Z1:         z1.Big(),
		Z2:         z2.Big(),
		W:          w.Big(),
	}
}

func (p *Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	e := challenge(hash, public, p.Commitment)

	if !public.Aux.Verify(p.Z1, p.Z2, p.T, p.S, e) {
		return false
	}

	{
		// lhs = Enc₀(z₁;w)
		lhs := public.Prover.EncWithNonce(p.Z1, p.W)

		// rhs = (e ⊙ C) ⊕ A
		rhs := public.C.Clone().Mul(public.Prover, e).Add(public.Prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = z₁ mod q
		lhs := curve.NewScalarBigInt(p.Z1)

		// rhs = e•x + γ
		rhs := curve.NewScalarBigInt(e)
		rhs.MultiplyAdd(rhs, public.X, p.Gamma)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment *Commitment) *big.Int {
	_, _ = hash.WriteAny(public.Aux, public.Prover,
		public.C, public.X,
		commitment.S, commitment.T, commitment.A, commitment.Gamma)

	return sample.IntervalScalar(hash)
}
