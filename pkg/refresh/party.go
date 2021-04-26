package refresh

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

// localParty is the state we store for a remote party.
// The messages are embedded to make access to the attributes easier.
type localParty struct {
	*party.Base

	PaillierPublic *paillier.PublicKey
	Pedersen       *pedersen.Parameters
	Public         *curve.Point
	PublicNew      *curve.Point

	X    []*curve.Point // Xⱼ
	ASch []*curve.Point // Aⱼ

	Y    *curve.Point
	BSch *curve.Point

	commitment []byte // H(msg2, decommitment)

	rho []byte // ρᵢ
}

func newParty(id uint32, public *curve.Point) *localParty {
	var X curve.Point
	X.Set(public)
	return &localParty{
		Base:   party.NewBaseParty(id),
		Public: &X,
	}
}
