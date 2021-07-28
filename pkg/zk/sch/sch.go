package zksch

import (
	"crypto/rand"
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

// NewProof generates a Schnorr proof of knowledge of exponent for public, using the Fiat-Shamir transform.
func NewProof(hash *hash.Hash, public *curve.Point, private *curve.Scalar) *Proof {
	a := NewRandomness(rand.Reader)
	z := a.Prove(hash, public, private)
	return &Proof{
		C: a.Commitment(),
		Z: z,
	}
}

// NewRandomness creates a new a ∈ ℤₚ and the corresponding commitment C = a•G.
// This can be used to run the proof in a non-interactive way.
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

// Prove creates a Response = Randomness + H(..., Commitment, public)•secret (mod p).
func (r *Randomness) Prove(hash *hash.Hash, public *curve.Point, secret *curve.Scalar) *Response {
	var p Response
	p.Z = *challenge(hash, &r.commitment, public)
	p.Z.MultiplyAdd(&p.Z, secret, &r.a)
	return &p
}

// Commitment returns the commitment C = a•G for the randomness a.
func (r *Randomness) Commitment() *Commitment {
	return &r.commitment
}

// Verify checks that Response•G = Commitment + H(..., Commitment, public)•Public.
func (z *Response) Verify(hash *hash.Hash, public *curve.Point, commitment *Commitment) bool {
	if !z.IsValid() || public.IsIdentity() {
		return false
	}

	e := challenge(hash, commitment, public)

	var lhs, rhs curve.Point
	lhs.ScalarBaseMult(&z.Z)
	rhs.ScalarMult(e, public)
	rhs.Add(&rhs, &commitment.C)

	return lhs.Equal(&rhs)
}

// Verify checks that Proof.Response•G = Proof.Commitment + H(..., Proof.Commitment, Public)•Public.
func (p *Proof) Verify(hash *hash.Hash, public *curve.Point) bool {
	if !p.IsValid() {
		return false
	}
	return p.Z.Verify(hash, public, p.C)
}

// WriteTo implements io.WriterTo.
func (c *Commitment) WriteTo(w io.Writer) (total int64, err error) {
	return c.C.WriteTo(w)
}

// Domain implements writer.WriterToWithDomain
func (Commitment) Domain() string {
	return "Schnorr Commitment"
}

func (c *Commitment) IsValid() bool {
	if c == nil || c.C.IsIdentity() {
		return false
	}
	return true
}

func (z *Response) IsValid() bool {
	if z == nil || z.Z.IsZero() {
		return false
	}
	return true
}

func (p *Proof) IsValid() bool {
	if p == nil || !p.Z.IsValid() || !p.C.IsValid() {
		return false
	}
	return true
}
