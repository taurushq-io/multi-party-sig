package xor

import (
	"crypto/rand"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

// StartXOR is a function that creates the first round with all necessary information to create a protocol.Handler
func StartXOR(selfID party.ID, partyIDs party.IDSlice) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		// create a hash function initialized with common information
		h := hash.New()
		_, err := h.WriteAny(partyIDs)
		if err != nil {
			return nil, nil, err
		}

		xor := make([]byte, 32)
		_, _ = rand.Read(xor)

		// create the helper with a description of the protocol
		helper := round.NewHelper("example/xor", 2, selfID, partyIDs, h)
		r := &Round1{
			Helper:   helper,
			received: map[party.ID][]byte{selfID: xor},
		}
		return r, helper, nil
	}
}
