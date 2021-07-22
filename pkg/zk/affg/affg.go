package zkaffg

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
		// C = Enc₀(?;?)
		// Kⱼ = Encⱼ(kⱼ; )
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

	Private struct {
		// X ∈ ± 2ˡ
		// Bob's multiplicative share
		X *safenum.Int

		// Y ∈ ± 2ˡº
		// Bob's additive share βᵢⱼ
		Y *safenum.Int

		// Rho = Nonce D = sᵢⱼ
		Rho *safenum.Nat

		// RhoY = Nonce Y = rᵢⱼ
		RhoY *safenum.Nat
	}
)

func (p Proof) IsValid(public Public) bool {
	if !public.Verifier.ValidateCiphertexts(p.A) {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.By) {
		return false
	}
	if !arith.IsValidModN(public.Prover.N(), p.Wy) {
		return false
	}
	if !arith.IsValidModN(public.Verifier.N(), p.W) {
		return false
	}
	if p.Bx.IsIdentity() {
		return false
	}
	return true
}

func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	N0Big := public.Verifier.N()
	N0 := safenum.ModulusFromNat(new(safenum.Nat).SetBig(N0Big, N0Big.BitLen()))
	N1Big := public.Prover.N()
	N1 := safenum.ModulusFromNat(new(safenum.Nat).SetBig(N1Big, N1Big.BitLen()))

	verifier := public.Verifier
	prover := public.Prover

	alpha := sample.IntervalLEpsSecret(rand.Reader)
	beta := sample.IntervalLPrimeEpsSecret(rand.Reader)

	r := sample.UnitModNNat(rand.Reader, N0)
	rY := sample.UnitModNNat(rand.Reader, N1)

	gamma := sample.IntervalLEpsNSecret(rand.Reader)
	m := sample.IntervalLEpsNSecret(rand.Reader)
	delta := sample.IntervalLEpsNSecret(rand.Reader)
	mu := sample.IntervalLNSecret(rand.Reader)

	cAlpha := public.C.Clone().Mul(verifier, alpha)           // = Cᵃ mod N₀ = α ⊙ C
	A := verifier.EncWithNonce(beta, r).Add(verifier, cAlpha) // = Enc₀(β,r) ⊕ (α ⊙ C)

	commitment := &Commitment{
		A:  A,
		Bx: *curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarInt(alpha)),
		By: prover.EncWithNonce(beta, rY),
		E:  public.Aux.Commit(alpha, gamma),
		S:  public.Aux.Commit(private.X, m),
		F:  public.Aux.Commit(beta, delta),
		T:  public.Aux.Commit(private.Y, mu),
	}

	eBig := challenge(hash, public, commitment)
	e := new(safenum.Int).SetBig(eBig, eBig.BitLen())

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
	w := new(safenum.Nat).ExpI(private.Rho, e, N0)
	w.ModMul(w, r, N0)
	// ( (ρy)ᵉ mod N₁)•ry mod N₁
	wY := new(safenum.Nat).ExpI(private.RhoY, e, N1)
	wY.ModMul(wY, rY, N1)

	return &Proof{
		Commitment: commitment,
		Z1:         z1.Big(),
		Z2:         z2.Big(),
		Z3:         z3.Big(),
		Z4:         z4.Big(),
		W:          w.Big(),
		Wy:         wY.Big(),
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

	e := challenge(hash, public, p.Commitment)

	if !public.Aux.Verify(p.Z1, p.Z3, p.E, p.S, e) {
		return false
	}

	if !public.Aux.Verify(p.Z2, p.Z4, p.F, p.T, e) {
		return false
	}

	z1 := new(safenum.Int).SetBig(p.Z1, p.Z1.BitLen())
	z2 := new(safenum.Int).SetBig(p.Z2, p.Z2.BitLen())
	w := new(safenum.Nat).SetBig(p.W, p.W.BitLen())
	wY := new(safenum.Nat).SetBig(p.Wy, p.Wy.BitLen())
	eInt := new(safenum.Int).SetBig(e, e.BitLen())

	{

		// tmp = z₁ ⊙ C
		// lhs = Enc₀(z₂;w) ⊕ z₁ ⊙ C
		tmp := public.C.Clone().Mul(verifier, z1)
		lhs := verifier.EncWithNonce(z2, w).Add(verifier, tmp)

		// rhs = (e ⊙ D) ⊕ A
		rhs := public.D.Clone().Mul(verifier, eInt).Add(verifier, p.A)

		if !lhs.Equal(rhs) {
			return false
		}
	}

	{

		// lhs = [z₁]G
		lhs := curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarBigInt(p.Z1))

		// rhsPt = Bₓ + [e]X
		rhs := curve.NewIdentityPoint().ScalarMult(curve.NewScalarBigInt(e), public.X)
		rhs.Add(&p.Bx, rhs)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = Enc₁(z₂; wy)
		lhs := prover.EncWithNonce(z2, wY)

		// rhs = (e ⊙ Y) ⊕ By
		rhs := public.Y.Clone().Mul(prover, eInt).Add(prover, p.By)

		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment *Commitment) *big.Int {
	_, _ = hash.WriteAny(public.Aux, public.Prover, public.Verifier,
		public.C, public.D, public.Y, public.X,
		commitment.A, commitment.Bx, commitment.By,
		commitment.E, commitment.S, commitment.F, commitment.T)

	return sample.IntervalScalar(hash)
}
