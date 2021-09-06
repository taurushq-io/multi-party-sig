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

// ConfigReceiver holds the results of key generation for the receiver.
type ConfigReceiver struct {
	// Setup is an implementation detail, needed to perform signing.
	Setup *ot.CorreOTReceiveSetup
	// SecretShare is a multiplicative share of the secret key.
	SecretShare curve.Scalar
	// Public is the shared public key.
	Public curve.Point
}

// Group returns the elliptic curve group associate with this config.
func (c *ConfigReceiver) Group() curve.Curve {
	return c.Public.Curve()
}

// ConfigSender holds the results of key generation for the sender.
type ConfigSender struct {
	// Setup is an implementation detail, needed to perform signing.
	Setup *ot.CorreOTSendSetup
	// SecretShare is a multiplicative share of the secret key.
	SecretShare curve.Scalar
	// Public is the shared public key.
	Public curve.Point
}

// Group returns the elliptic curve group associate with this config.
func (c *ConfigSender) Group() curve.Curve {
	return c.Public.Curve()
}

// StartKeygen starts the key generation protocol.
//
// This is documented further in the base doerner package.
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
