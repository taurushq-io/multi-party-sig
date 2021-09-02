package example

import (
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/example/xor"
)

const (
	protocolID                  = "example/xor"
	protocolRounds round.Number = 2
)

// StartXOR is a function that creates the first round with all necessary information to create a protocol.Handler.
func StartXOR(selfID party.ID, partyIDs party.IDSlice) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		info := round.Info{
			ProtocolID:       protocolID,
			FinalRoundNumber: protocolRounds,
			SelfID:           selfID,
			PartyIDs:         partyIDs,
		}
		// create the helper with a description of the protocol
		helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("xor: %w", err)
		}
		r := &xor.Round1{
			Helper: helper,
		}
		return r, nil
	}
}
