package zksch

import (
	"crypto/rand"
	"io"

	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

// Randomness = a ← ℤₚ.
type Randomness struct {
	a          curve.Scalar
	commitment Commitment
}

// Commitment = randomness•G, where
type Commitment struct {
	C curve.Point
}

// Response = randomness + H(..., commitment, public)•secret (mod p).
type Response struct {
	group curve.Curve
	Z     curve.Scalar
}

type Proof struct {
	C Commitment
	Z Response
}

// NewProof generates a Schnorr proof of knowledge of exponent for public, using the Fiat-Shamir transform.
func NewProof(hash *hash.Hash, public curve.Point, private curve.Scalar, gen curve.Point) *Proof {
	group := private.Curve()

	a := NewRandomness(rand.Reader, group, gen)
	z := a.Prove(hash, public, private, gen)
	return &Proof{
		C: *a.Commitment(),
		Z: *z,
	}
}

// NewRandomness creates a new a ∈ ℤₚ and the corresponding commitment C = a•G.
// This can be used to run the proof in a non-interactive way.
func NewRandomness(rand io.Reader, group curve.Curve, gen curve.Point) *Randomness {
	if gen == nil {
		gen = group.NewBasePoint()
	}
	a := sample.Scalar(rand, group)
	return &Randomness{
		a:          a,
		commitment: Commitment{C: a.Act(gen)},
	}
}

func challenge(hash *hash.Hash, group curve.Curve, commitment *Commitment, public, gen curve.Point) (e curve.Scalar, err error) {
	err = hash.WriteAny(commitment.C, public, gen)
	e = sample.Scalar(hash.Digest(), group)
	return
}

// Prove creates a Response = Randomness + H(..., Commitment, public)•secret (mod p).
func (r *Randomness) Prove(hash *hash.Hash, public curve.Point, secret curve.Scalar, gen curve.Point) *Response {
	if gen == nil {
		gen = public.Curve().NewBasePoint()
	}
	if public.IsIdentity() || secret.IsZero() {
		return nil
	}
	group := secret.Curve()
	e, err := challenge(hash, group, &r.commitment, public, gen)
	if err != nil {
		return nil
	}
	es := e.Mul(secret)
	z := es.Add(r.a)
	return &Response{group: group, Z: z}
}

// Commitment returns the commitment C = a•G for the randomness a.
func (r *Randomness) Commitment() *Commitment {
	return &r.commitment
}

// Verify checks that Response•G = Commitment + H(..., Commitment, public)•Public.
func (z *Response) Verify(hash *hash.Hash, public curve.Point, commitment *Commitment, gen curve.Point) bool {
	if gen == nil {
		gen = public.Curve().NewBasePoint()
	}
	if z == nil || !z.IsValid() || public.IsIdentity() {
		return false
	}

	e, err := challenge(hash, z.group, commitment, public, gen)
	if err != nil {
		return false
	}

	lhs := z.Z.Act(gen)
	rhs := e.Act(public)
	rhs = rhs.Add(commitment.C)

	return lhs.Equal(rhs)
}

// Verify checks that Proof.Response•G = Proof.Commitment + H(..., Proof.Commitment, Public)•Public.
func (p *Proof) Verify(hash *hash.Hash, public, gen curve.Point) bool {
	if !p.IsValid() {
		return false
	}
	return p.Z.Verify(hash, public, &p.C, gen)
}

// WriteTo implements io.WriterTo.
func (c *Commitment) WriteTo(w io.Writer) (int64, error) {
	data, err := c.C.MarshalBinary()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(data)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain
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

func EmptyProof(group curve.Curve) *Proof {
	return &Proof{
		C: Commitment{C: group.NewPoint()},
		Z: Response{group: group, Z: group.NewScalar()},
	}
}

func EmptyResponse(group curve.Curve) *Response {
	return &Response{group: group, Z: group.NewScalar()}
}

func EmptyCommitment(group curve.Curve) *Commitment {
	return &Commitment{C: group.NewPoint()}
}
