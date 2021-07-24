package zksch

import (
	"io"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
)

// Randomness = a ← ℤₚ.
type Randomness struct {
	a          curve.Scalar
	commitment Commitment
}

func NewRandomness(rand io.Reader) *Randomness {
	var r Randomness
	r.a = *sample.Scalar(rand)
	r.commitment.C.ScalarBaseMult(&r.a)
	return &r
}

func challenge(hash *hash.Hash, commitment *Commitment, public *curve.Point) *curve.Scalar {
	_, _ = hash.WriteAny(&commitment.C, public)
	return sample.Scalar(hash)
}

// Prove creates a Proof = Randomness + H(..., Commitment, public)•secret (mod p).
func (r *Randomness) Prove(hash *hash.Hash, public *curve.Point, secret *curve.Scalar) *Proof {
	var p Proof
	p.Z = *challenge(hash, &r.commitment, public)
	p.Z.MultiplyAdd(&p.Z, secret, &r.a)
	return &p
}

// Commitment returns the commitment for the randomness.
func (r *Randomness) Commitment() *Commitment {
	return &r.commitment
}

// Verify checks that Proof•G = Commitment + H(..., Commitment, public)•Public.
func (p *Proof) Verify(hash *hash.Hash, public *curve.Point, commitment *Commitment) bool {
	if commitment == nil || public == nil {
		return false
	}

	if commitment.C.IsIdentity() || public.IsIdentity() {
		return false
	}

	e := challenge(hash, commitment, public)

	var lhs, rhs curve.Point
	lhs.ScalarBaseMult(&p.Z)
	rhs.ScalarMult(e, public)
	rhs.Add(&rhs, &commitment.C)

	return lhs.Equal(&rhs)
}

func (c *Commitment) WriteTo(w io.Writer) (total int64, err error) {
	return c.C.WriteTo(w)
}

func (Commitment) Domain() string {
	return "Schnorr Commitment"
}
