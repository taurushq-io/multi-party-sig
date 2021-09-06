package sign

import (
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/doerner/keygen"
)

// StartSignReceiver starts the signature protocol for the receiver.
func StartSignReceiver(config *keygen.ConfigReceiver, selfID, otherID party.ID, hash []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		info := round.Info{
			ProtocolID:       "doerner/keygen",
			FinalRoundNumber: 2,
			SelfID:           selfID,
			PartyIDs:         party.NewIDSlice([]party.ID{selfID, otherID}),
			Threshold:        1,
			Group:            config.Group(),
		}

		helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("keygen.StartKeygen: %w", err)
		}

		return &round1R{Helper: helper, config: config, hash: hash}, nil
	}
}

// StartSignSender starts the signature protocol for the sender.
func StartSignSender(config *keygen.ConfigSender, selfID, otherID party.ID, hash []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		info := round.Info{
			ProtocolID:       "doerner/keygen",
			FinalRoundNumber: 2,
			SelfID:           selfID,
			PartyIDs:         party.NewIDSlice([]party.ID{selfID, otherID}),
			Threshold:        1,
			Group:            config.Group(),
		}

		helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("keygen.StartKeygen: %w", err)
		}

		return &round1S{Helper: helper, config: config, hash: hash}, nil
	}
}
