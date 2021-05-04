package refresh

import (
	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

// localParty is the state we store for a remote party.
// The messages are embedded to make access to the attributes easier.
type localParty struct {
	*party.Base

	index int

	PaillierPublic *paillier.PublicKey
	Pedersen       *pedersen.Parameters
	Public         *curve.Point
	PublicNew      *curve.Point

	X    []*curve.Point // Xⱼ
	ASch []*curve.Point // Aⱼ

	Y    *curve.Point
	BSch *curve.Point

	commitment hash.Commitment // H(msg2, decommitment)

	rho []byte // ρᵢ

	refresh1 *pb.Refresh1
	refresh2 *pb.Refresh2
	refresh3 *pb.Refresh3
}

func newParty(id party.ID, index int, public *curve.Point) *localParty {
	var X curve.Point
	X.Set(public)
	return &localParty{
		Base:   party.NewBaseParty(id),
		index:  index,
		Public: &X,
	}
}
