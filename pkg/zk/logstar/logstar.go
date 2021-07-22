package zklogstar

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
		// C = Enc₀(x;ρ)
		// Encryption of x under the prover's key
		C *paillier.Ciphertext

		// X = [x] G
		// x "in the exponent"
		X *curve.Point

		// G = Base point of the curve,
		// If G = nil, the default base point is used
		G *curve.Point

		Prover *paillier.PublicKey
		Aux    *pedersen.Parameters
	}
	Private struct {
		// X is the plaintext of C and the dlog of X
		X *safenum.Int

		// Rho = ρ
		// nonce of C
		Rho *safenum.Nat
	}
)

func (p Proof) IsValid(public Public) bool {
	if !public.Prover.ValidateCiphertexts(p.A) {
		return false
	}
	if p.Y.IsIdentity() {
		return false
	}
	if !arith.IsValidModN(public.Prover.N(), p.Z2) {
		return false
	}
	return true
}

func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	NBig := public.Prover.N()
	N := safenum.ModulusFromNat(new(safenum.Nat).SetBig(NBig, NBig.BitLen()))

	if public.G == nil {
		public.G = curve.NewBasePoint()
	}

	alpha := sample.IntervalLEpsSecret(rand.Reader)
	r := sample.UnitModN(rand.Reader, N)
	mu := sample.IntervalLNSecret(rand.Reader)
	gamma := sample.IntervalLEpsNSecret(rand.Reader)

	commitment := &Commitment{
		A: public.Prover.EncWithNonce(alpha, r),
		Y: *curve.NewIdentityPoint().ScalarMult(curve.NewScalarInt(alpha), public.G),
		S: public.Aux.Commit(private.X, mu),
		D: public.Aux.Commit(alpha, gamma),
	}

	eBig := challenge(hash, public, commitment)
	e := new(safenum.Int).SetBig(eBig, eBig.BitLen())

	// z1 = α + e x,
	z1 := new(safenum.Int).Mul(e, private.X, -1)
	z1.Add(z1, alpha, -1)
	// z2 = r ρᵉ mod Nₐ,
	z2 := new(safenum.Nat).ExpI(private.Rho, e, N)
	z2.ModMul(z2, r, N)
	// z3 = γ + e μ,
	z3 := new(safenum.Int).Mul(e, mu, -1)
	z3.Add(z3, gamma, -1)

	return &Proof{
		Commitment: commitment,
		Z1:         z1.Big(),
		Z2:         z2.Big(),
		Z3:         z3.Big(),
	}
}

func (p Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	if public.G == nil {
		public.G = curve.NewBasePoint()
	}

	if !arith.IsInIntervalLPrimeEps(p.Z1) {
		return false
	}

	prover := public.Prover

	e := challenge(hash, public, p.Commitment)

	if !public.Aux.Verify(p.Z1, p.Z3, p.D, p.S, e) {
		return false
	}

	z1 := new(safenum.Int).SetBig(p.Z1, p.Z1.BitLen())
	z2 := new(safenum.Nat).SetBig(p.Z2, p.Z2.BitLen())
	eInt := new(safenum.Int).SetBig(e, e.BitLen())

	{
		// lhs = Enc(z₁;z₂)
		lhs := prover.EncWithNonce(z1, z2)

		// rhs = (e ⊙ C) ⊕ A
		rhs := public.C.Clone().Mul(prover, eInt).Add(prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = [z₁]G
		lhs := curve.NewIdentityPoint().ScalarMult(curve.NewScalarBigInt(p.Z1), public.G)

		// rhs = Y + [e]X
		eX := curve.NewIdentityPoint().ScalarMult(curve.NewScalarBigInt(e), public.X)
		rhs := curve.NewIdentityPoint().Add(&p.Y, eX)

		if !lhs.Equal(rhs) {
			return false
		}

	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment *Commitment) *big.Int {
	_, _ = hash.WriteAny(public.Aux, public.Prover, public.C, public.X, public.G,
		commitment.S, commitment.A, commitment.Y, commitment.D)

	return sample.IntervalScalar(hash)
}
