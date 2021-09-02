package zklog

import (
	"crypto/rand"

	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

type Public struct {
	// H = b⋅G
	H curve.Point

	// X = a⋅G
	X curve.Point

	// Y = a⋅H
	Y curve.Point
}

type Private struct {
	// A = a
	A curve.Scalar
	// B = b
	B curve.Scalar
}

type Commitment struct {
	// A = α⋅G
	A curve.Point
	// B = α⋅H
	B curve.Point
	// C = β⋅G
	C curve.Point
}

type Proof struct {
	group curve.Curve
	*Commitment

	// Z1 = α+ea (mod q)
	Z1 curve.Scalar
	// Z2 = β+eb (mod q)
	Z2 curve.Scalar
}

func (p *Proof) IsValid() bool {
	if p == nil {
		return false
	}
	if p.A.IsIdentity() || p.B.IsIdentity() || p.C.IsIdentity() {
		return false
	}
	if p.Z1.IsZero() || p.Z2.IsZero() {
		return false
	}
	return true
}

func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	alpha := sample.Scalar(rand.Reader, group)
	beta := sample.Scalar(rand.Reader, group)

	commitment := &Commitment{
		A: alpha.ActOnBase(),   // A = α⋅G
		B: alpha.Act(public.H), // B = α⋅H
		C: beta.ActOnBase(),    // C = β⋅H
	}
	e, _ := challenge(hash, group, public, commitment)

	return &Proof{
		group:      group,
		Commitment: commitment,
		Z1:         group.NewScalar().Set(e).Mul(private.A).Add(alpha), // Z₁ = α+ea (mod q)
		Z2:         group.NewScalar().Set(e).Mul(private.B).Add(beta),  // Z₂ = β+eb (mod q)
	}
}

func (p Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid() {
		return false
	}

	e, err := challenge(hash, p.group, public, p.Commitment)
	if err != nil {
		return false
	}

	{
		lhs := p.Z1.ActOnBase()         // lhs = z₁⋅G
		rhs := e.Act(public.X).Add(p.A) // rhs = A+e⋅X
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		lhs := p.Z1.Act(public.H)       // lhs = z₁⋅H
		rhs := e.Act(public.Y).Add(p.B) // rhs = B+e⋅Y
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		lhs := p.Z2.ActOnBase()         // lhs = z₂⋅G
		rhs := e.Act(public.H).Add(p.C) // rhs = C+e⋅H
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e curve.Scalar, err error) {
	err = hash.WriteAny(public.H, public.X, public.Y,
		commitment.A, commitment.B, commitment.C)
	e = sample.Scalar(hash.Digest(), group)
	return
}

func Empty(group curve.Curve) *Proof {
	return &Proof{
		group: group,
		Commitment: &Commitment{
			A: group.NewPoint(),
			B: group.NewPoint(),
			C: group.NewPoint(),
		},
		Z1: group.NewScalar(),
		Z2: group.NewScalar(),
	}
}
