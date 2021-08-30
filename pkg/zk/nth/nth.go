// zknth is based on the zkenc package,
// and can be seen as the special case where the ciphertext encrypts the "0" value.
package zknth

import (
	"crypto/rand"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
)

type Public struct {
	// N
	N *paillier.PublicKey

	// R = r = ρᴺ (mod N²)
	R *safenum.Nat
}

type Private struct {
	// Rho = ρ
	Rho *safenum.Nat
}

type Commitment struct {
	// A = αᴺ (mod N²)
	A *safenum.Nat
}

type Proof struct {
	Commitment
	// Z = αρᴺ (mod N²)
	Z *safenum.Nat
}

func (p *Proof) IsValid(public Public) bool {
	if !arith.IsValidNatModN(public.N.N(), p.Z) {
		return false
	}

	if !arith.IsValidNatModN(public.N.ModulusSquared().Modulus, p.A) {
		return false
	}

	return true
}

// NewProof generates a proof that r = ρᴺ (mod N²).
func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	N := public.N.N()
	// α ← ℤₙˣ
	alpha := sample.UnitModN(rand.Reader, N)
	// A = αⁿ (mod n²)
	A := public.N.ModulusSquared().Exp(alpha, N.Nat())
	commitment := Commitment{
		A: A,
	}
	e, _ := challenge(hash, public, commitment)
	// Z = αρᵉ (mod N)
	Z := public.N.Modulus().ExpI(private.Rho, e)
	Z.ModMul(Z, alpha, N)
	return &Proof{
		Commitment: commitment,
		Z:          Z,
	}
}

func (p *Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	e, err := challenge(hash, public, p.Commitment)
	if err != nil {
		return false
	}

	NSquared := public.N.ModulusSquared()
	lhs := NSquared.Exp(p.Z, public.N.N().Nat())
	rhs := NSquared.ExpI(public.R, e)
	rhs.ModMul(rhs, p.A, NSquared.Modulus)
	if lhs.Eq(rhs) != 1 {
		return false
	}
	return true
}

func challenge(hash *hash.Hash, public Public, commitment Commitment) (e *safenum.Int, err error) {
	err = hash.WriteAny(public.N, public.R, commitment.A)
	e = sample.IntervalL(hash.Digest())
	return
}
