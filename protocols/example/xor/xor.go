package xor

import (
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

// StartXOR is a function that creates the first round with all necessary information to create a protocol.Handler.
func StartXOR(selfID party.ID, partyIDs party.IDSlice) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		// create a hash function initialized with common information
		h := hash.New()
		if err := h.WriteAny(partyIDs); err != nil {
			return nil, nil, err
		}

		// create the helper with a description of the protocol
		helper, err := round.NewHelper("example/xor", nil, 2, selfID, partyIDs)
		if err != nil {
			return nil, nil, fmt.Errorf("xor: %w", err)
		}
		r := &Round1{
			Helper: helper,
		}
		return r, helper, nil
	}
}
