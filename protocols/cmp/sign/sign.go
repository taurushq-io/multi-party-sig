package sign

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
)

// protocolSignID for the "3 round" variant using echo broadcast.
const (
	protocolSignID                  = "cmp/sign"
	protocolSignRounds round.Number = 5
)

func StartSign(config *config.Config, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		group := config.Group()

		// this could be used to indicate a pre-signature later on
		if len(message) == 0 {
			return nil, errors.New("sign.Create: message is nil")
		}

		// validate config
		if err := config.Validate(); err != nil {
			return nil, err
		}

		info := round.Info{
			ProtocolID:       protocolSignID,
			FinalRoundNumber: protocolSignRounds,
			SelfID:           config.ID,
			PartyIDs:         signers,
			Threshold:        config.Threshold,
			Group:            config.Group,
		}

		helper, err := round.NewSession(info, sessionID, pl, config, types.SigningMessage(message))
		if err != nil {
			return nil, fmt.Errorf("sign.Create: %w", err)
		}

		if !config.CanSign(helper.PartyIDs()) {
			return nil, errors.New("sign.Create: signers is not a valid signing subset")
		}

		// Scale public data
		T := helper.N()
		ECDSA := make(map[party.ID]curve.Point, T)
		Paillier := make(map[party.ID]*paillier.PublicKey, T)
		Pedersen := make(map[party.ID]*pedersen.Parameters, T)
		PublicKey := group.NewPoint()
		lagrange := polynomial.Lagrange(group, signers)
		// Scale own secret
		SecretECDSA := group.NewScalar().Set(lagrange[config.ID]).Mul(config.ECDSA)
<<<<<<< HEAD
		SecretPaillier := config.PaillierSecret()
		for _, j := range helper.PartyIDs() {
			public := config.Public[j]
=======
		SecretPaillier := config.Paillier()
		for _, j := range signerIDs {
			public := config.Public.Data[j]
>>>>>>> 827425ff5c6818fdb6d5739b9b6d836a9aa339c4
			// scale public key share
			ECDSA[j] = lagrange[j].Act(public.ECDSA)
			// create Paillier key, but set ours to the one derived from the private key
			// since it includes the CRT acceleration.
			if j == config.ID {
				Paillier[j] = SecretPaillier.PublicKey
			} else {
				Paillier[j] = paillier.NewPublicKey(public.N)
			}
			// create Pedersen params
			Pedersen[j] = pedersen.New(Paillier[j].Modulus(), public.S, public.T)
			PublicKey = PublicKey.Add(ECDSA[j])
		}

		return &round1{
			Helper:         helper,
			PublicKey:      PublicKey,
			SecretECDSA:    SecretECDSA,
			SecretPaillier: config.PaillierSecret(),
			Paillier:       Paillier,
			Pedersen:       Pedersen,
			ECDSA:          ECDSA,
			Message:        message,
		}, nil
	}
}
