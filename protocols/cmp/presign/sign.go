package presign

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
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

func StartPresign(pl *pool.Pool, c *config.Config, signers []party.ID, message []byte) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		group := c.Group

		// this could be used to indicate a pre-signature later on
		var (
			rounds     round.Number
			protocolID string
		)
		if len(message) == 0 {
			rounds = protocolOfflineRounds
			protocolID = protocolOfflineID
		} else {
			rounds = protocolFullRounds
			protocolID = protocolFullID
		}

		signerIDs := party.NewIDSlice(signers)
		if !c.CanSign(signerIDs) {
			return nil, nil, errors.New("sign.Create: signers is not a valid signing subset")
		}

		// validate config
		if err := c.Validate(); err != nil {
			return nil, nil, err
		}

		helper, err := round.NewHelper(
			protocolID,
			group,
			rounds,
			c.ID,
			signerIDs,
			// write the config, the signers and the message to this session.
			c,
			signerIDs,
			hash.BytesWithDomain{
				TheDomain: "Signature Message",
				Bytes:     message,
			},
		)
		if err != nil {
			return nil, nil, fmt.Errorf("sign.Create: %w", err)
		}

		// Scale public data
		T := len(signerIDs)
		ECDSA := make(map[party.ID]curve.Point, T)
		ElGamal := make(map[party.ID]curve.Point, T)
		Paillier := make(map[party.ID]*paillier.PublicKey, T)
		Pedersen := make(map[party.ID]*pedersen.Parameters, T)
		PublicKey := group.NewPoint()
		lagrange := polynomial.Lagrange(group, signers)
		// Scale own secret
		SecretECDSA := group.NewScalar().Set(lagrange[c.ID]).Mul(c.ECDSA)
		SecretPaillier := c.Paillier()
		for _, j := range signerIDs {
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
			SecretPaillier: c.Paillier(),
			PublicKey:      PublicKey,
			ECDSA:          ECDSA,
			ElGamal:        ElGamal,
			Paillier:       Paillier,
			Pedersen:       Pedersen,
			Message:        message,
		}, helper, nil
	}
}

func StartPresignOnline(c *config.Config, preSignature *ecdsa.PreSignature, message []byte) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		group := preSignature.Group

		// this could be used to indicate a pre-signature later on
		if len(message) == 0 {
			return nil, nil, errors.New("sign.Create: message is nil")
		}

		if err := preSignature.Validate(); err != nil {
			return nil, nil, err
		}

		signers := preSignature.SignerIDs()

		if !c.CanSign(signers) {
			return nil, nil, errors.New("sign.Create: signers is not a valid signing subset")
		}

		// validate config
		if err := c.Validate(); err != nil {
			return nil, nil, err
		}

		helper, err := round.NewHelper(
			protocolOnlineID,
			group,
			protocolOnlineRounds,
			c.ID,
			signers,
			// write the config, the signers, presignature ID, and the message to this session.
			c,
			signers,
			hash.BytesWithDomain{
				TheDomain: "PreSignatureID",
				Bytes:     preSignature.ID,
			},
			hash.BytesWithDomain{
				TheDomain: "Signature Message",
				Bytes:     message,
			},
		)
		if err != nil {
			return nil, nil, fmt.Errorf("sign.Create: %w", err)
		}

		return &sign1{
			Helper:       helper,
			PublicKey:    c.PublicPoint(),
			Message:      message,
			PreSignature: preSignature,
		}, helper, nil
	}
}
