package presign

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
)

const (
	protocolOfflineID                  = "cmp/presign-offline"
	protocolOnlineID                   = "cmp/presign-online"
	protocolFullID                     = "cmp/presign-full"
	protocolOfflineRounds round.Number = 7
	protocolOnlineRounds  round.Number = 2
	protocolFullRounds    round.Number = 8
)

func StartPresign(c *config.Config, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// validate config
		if err := c.Validate(); err != nil {
			return nil, err
		}

		info := round.Info{
			SelfID:    c.ID,
			PartyIDs:  signers,
			Threshold: c.Threshold,
			Group:     c.Group,
		}
		if len(message) == 0 {
			info.FinalRoundNumber = protocolOfflineRounds
			info.ProtocolID = protocolOfflineID
		} else {
			info.FinalRoundNumber = protocolFullRounds
			info.ProtocolID = protocolFullID
		}

		helper, err := round.NewSession(info, sessionID, pl, c, types.SigningMessage(message))
		if err != nil {
			return nil, fmt.Errorf("sign.Create: %w", err)
		}

		if !c.CanSign(helper.PartyIDs()) {
			return nil, errors.New("sign.Create: signers is not a valid signing subset")
		}
		// Scale public data
		T := helper.N()
		group := c.Group
		ECDSA := make(map[party.ID]curve.Point, T)
		ElGamal := make(map[party.ID]curve.Point, T)
		Paillier := make(map[party.ID]*paillier.PublicKey, T)
		Pedersen := make(map[party.ID]*pedersen.Parameters, T)
		PublicKey := group.NewPoint()
		lagrange := polynomial.Lagrange(group, signers)
		// Scale own secret
		SecretECDSA := group.NewScalar().Set(lagrange[c.ID]).Mul(c.ECDSA)
		SecretPaillier := c.PaillierSecret()
		for _, j := range helper.PartyIDs() {
			public := c.Public[j]
			// scale public key share
			ECDSA[j] = lagrange[j].Act(public.ECDSA)
			ElGamal[j] = public.ElGamal
			// create Paillier key, but set ours to the oneNat derived from the private key
			// since it includes the CRT acceleration.
			if j == c.ID {
				Paillier[j] = SecretPaillier.PublicKey
			} else {
				Paillier[j] = paillier.NewPublicKey(public.N)
			}
			// create Pedersen params
			Pedersen[j] = pedersen.New(Paillier[j].Modulus(), public.S, public.T)
			PublicKey = PublicKey.Add(ECDSA[j])
		}

		return &presign1{
			Helper:         helper,
			Pool:           pl,
			SecretECDSA:    SecretECDSA,
			SecretElGamal:  c.ElGamal,
			SecretPaillier: c.PaillierSecret(),
			PublicKey:      PublicKey,
			ECDSA:          ECDSA,
			ElGamal:        ElGamal,
			Paillier:       Paillier,
			Pedersen:       Pedersen,
			Message:        message,
		}, nil
	}
}

func StartPresignOnline(c *config.Config, preSignature *ecdsa.PreSignature, message []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// this could be used to indicate a pre-signature later on
		if len(message) == 0 {
			return nil, errors.New("sign.Create: message is nil")
		}

		if err := preSignature.Validate(); err != nil {
			return nil, fmt.Errorf("sign.Create: %w", err)
		}

		signers := preSignature.SignerIDs()

		if !c.CanSign(signers) {
			return nil, errors.New("sign.Create: signers is not a valid signing subset")
		}

		// validate config
		if err := c.Validate(); err != nil {
			return nil, err
		}

		info := round.Info{
			ProtocolID:       protocolOnlineID,
			FinalRoundNumber: protocolOnlineRounds,
			SelfID:           c.ID,
			PartyIDs:         signers,
			Threshold:        c.Threshold,
			Group:            c.Group,
		}

		helper, err := round.NewSession(
			info,
			sessionID,
			pl,
			c,
			hash.BytesWithDomain{
				TheDomain: "PreSignatureID",
				Bytes:     preSignature.ID,
			},
			types.SigningMessage(message),
		)
		if err != nil {
			return nil, fmt.Errorf("sign.Create: %w", err)
		}

		return &sign1{
			Helper:       helper,
			PublicKey:    c.PublicPoint(),
			Message:      message,
			PreSignature: preSignature,
		}, nil
	}
}
