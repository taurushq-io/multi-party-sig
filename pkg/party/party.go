package party

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

type Public struct {
	ID ID

	Paillier *paillier.PublicKey
	ECDSA    *curve.Point
	Pedersen *pedersen.Parameters
}

// NewPublic returns a Public struct.
// If public is nil, then no fields are set since this would lead to an inconsistent state
func NewPublic(id ID, public *curve.Point, ped *pedersen.Parameters) *Public {
	p := &Public{ID: id}

	if public == nil {
		return p
	}
	p.ECDSA = curve.NewIdentityPoint().Set(public)

	if ped != nil {
		p.Pedersen = ped.Clone()
		p.Paillier = paillier.NewPublicKey(ped.N)
	}

	return p
}

func (p *Public) Clone() *Public {
	p2 := &Public{ID: p.ID}

	if p.Paillier != nil {
		p2.Paillier = paillier.NewPublicKey(p.Paillier.N)
	}
	if p.ECDSA != nil {
		p2.ECDSA = curve.NewIdentityPoint().Set(p.ECDSA)
	}
	if p.Pedersen != nil {
		p2.Pedersen = p.Pedersen.Clone()
	}
	return p2
}

func (p *Public) IsValid() error {
	if p.ECDSA == nil && (p.Pedersen != nil || p.Paillier != nil) {
		return errors.New("ECDSA key cannot be nil if other parameters are present")
	}

	if p.ECDSA != nil && p.ECDSA.IsIdentity() {
		return errors.New("ecdsa key is 0")
	}

	if p.Paillier != nil && !p.Paillier.IsValid() {
		return errors.New("paillier key invalid")
	}

	if p.Pedersen != nil && !p.Pedersen.IsValid() {
		return errors.New("pedersen parameters invalid")
	}

	return nil
}
