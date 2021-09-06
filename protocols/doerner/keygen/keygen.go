package keygen

import (
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

type ConfigReceiver struct {
	Setup       *ot.CorreOTReceiveSetup
	SecretShare curve.Scalar
	Public      curve.Point
}

func (c *ConfigReceiver) Group() curve.Curve {
	return c.Public.Curve()
}

type ConfigSender struct {
	Setup       *ot.CorreOTSendSetup
	SecretShare curve.Scalar
	Public      curve.Point
}

func (c *ConfigSender) Group() curve.Curve {
	return c.Public.Curve()
}

func StartKeygen(group curve.Curve, receiver bool, selfID, otherID party.ID, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		info := round.Info{
			ProtocolID:       "doerner/keygen",
			FinalRoundNumber: 3,
			SelfID:           selfID,
			PartyIDs:         party.NewIDSlice([]party.ID{selfID, otherID}),
			Threshold:        1,
			Group:            group,
		}

		helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("keygen.StartKeygen: %w", err)
		}

		if receiver {
			return &round1R{Helper: helper, receiver: ot.NewCorreOTSetupReceiver(pl, helper.Hash(), helper.Group())}, nil
		}
		return &round1S{Helper: helper, sender: ot.NewCorreOTSetupSender(pl, helper.Hash())}, nil
	}
}
