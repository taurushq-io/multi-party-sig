package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

// localParty is the state we store for a remote party.
// The messages are embedded to make access to the attributes easier.
type localParty struct {
	*party.Base

	commitment []byte // H(msg2, decommitment)

	rid []byte       // ridᵢ
	X   *curve.Point // Xᵢ = [xᵢ] G
	A   *curve.Point // Aᵢ = [aᵢ] G

	keygen1 *pb.Keygen1
	keygen2 *pb.Keygen2
	keygen3 *pb.Keygen3
}

func newParty(id party.ID) *localParty {
	return &localParty{
		Base: party.NewBaseParty(id),
	}
}

// TODO Methods for unmarshalling ProtoBufs the party
