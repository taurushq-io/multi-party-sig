package keygen

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/bip32"
	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

// ConfigReceiver holds the results of key generation for the receiver.
type ConfigReceiver struct {
	// Setup is an implementation detail, needed to perform signing.
	Setup *ot.CorreOTReceiveSetup
	// SecretShare is an additive share of the secret key.
	SecretShare curve.Scalar
	// Public is the shared public key.
	Public curve.Point
	// ChainKey is the shared chain key.
	ChainKey []byte
}

// Group returns the elliptic curve group associate with this config.
func (c *ConfigReceiver) Group() curve.Curve {
	return c.Public.Curve()
}

// Derive performs an arbitrary derivation of a related key, by adding a scalar.
//
// This can support methods like BIP32, but is more general.
//
// Optionally, a new chain key can be passed as well.
func (c *ConfigReceiver) Derive(adjust curve.Scalar, newChainKey []byte) (*ConfigReceiver, error) {
	if len(newChainKey) <= 0 {
		newChainKey = c.ChainKey
	}
	if len(newChainKey) != params.SecBytes {
		return nil, fmt.Errorf("expecte %d bytes for chain key, found %d", params.SecBytes, len(newChainKey))
	}

	adjustG := adjust.ActOnBase()

	return &ConfigReceiver{
		Setup:       c.Setup,
		SecretShare: c.SecretShare.Curve().NewScalar().Set(c.SecretShare).Add(adjust),
		Public:      c.Public.Add(adjustG),
	}, nil
}

// DeriveChild adjusts the shares to represent the derived public key at a certain index.
//
// This will panic if the group is not curve.Secp256k1
//
// This derivation works according to BIP-32, see:
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func (c *ConfigReceiver) DeriveBIP32(i uint32) (*ConfigReceiver, error) {
	publicKey, ok := c.Public.(*curve.Secp256k1Point)
	if !ok {
		return nil, errors.New("DeriveChild called on non secp256k1 curve")
	}
	scalar, newChainKey, err := bip32.DeriveScalar(publicKey, c.ChainKey, i)
	if err != nil {
		return nil, err
	}
	return c.Derive(scalar, newChainKey)
}

// ConfigSender holds the results of key generation for the sender.
type ConfigSender struct {
	// Setup is an implementation detail, needed to perform signing.
	Setup *ot.CorreOTSendSetup
	// SecretShare is an additive share of the secret key.
	SecretShare curve.Scalar
	// Public is the shared public key.
	Public curve.Point
	// ChainKey is the shared chain key.
	ChainKey []byte
}

// Group returns the elliptic curve group associate with this config.
func (c *ConfigSender) Group() curve.Curve {
	return c.Public.Curve()
}

// StartKeygen starts the key generation protocol.
//
// This is documented further in the base doerner package.
//
// This corresponds to protocol 2 of https://eprint.iacr.org/2018/499, with some adjustments
// to do additive sharing instead of multiplicative sharing.
//
// The Receiver plays the role of "Bob", and the Sender plays the role of "Alice".
//
// If the secret share and public point are not nil, a refresh is done instead.
func StartKeygen(group curve.Curve, receiver bool, selfID, otherID party.ID, secretShare curve.Scalar, public curve.Point, pl *pool.Pool) protocol.StartFunc {
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

		refresh := true
		if secretShare == nil && public == nil {
			secretShare = sample.Scalar(rand.Reader, group)
			refresh = false
		}
		publicShare := secretShare.ActOnBase()

		if receiver {
			return &round1R{
				Helper:      helper,
				refresh:     refresh,
				secretShare: secretShare,
				publicShare: publicShare,
				public:      public,
				receiver:    ot.NewCorreOTSetupReceiver(pl, helper.Hash(), helper.Group()),
			}, nil
		}
		return &round1S{
			Helper:      helper,
			refresh:     refresh,
			secretShare: secretShare,
			publicShare: publicShare,
			public:      public,
			sender:      ot.NewCorreOTSetupSender(pl, helper.Hash()),
		}, nil
	}
}

// Derive performs an arbitrary derivation of a related key, by adding a scalar.
//
// This can support methods like BIP32, but is more general.
//
// Optionally, a new chain key can be passed as well.
func (c *ConfigSender) Derive(adjust curve.Scalar, newChainKey []byte) (*ConfigSender, error) {
	if len(newChainKey) <= 0 {
		newChainKey = c.ChainKey
	}
	if len(newChainKey) != params.SecBytes {
		return nil, fmt.Errorf("expecte %d bytes for chain key, found %d", params.SecBytes, len(newChainKey))
	}

	adjustG := adjust.ActOnBase()

	return &ConfigSender{
		Setup:       c.Setup,
		SecretShare: c.SecretShare.Curve().NewScalar().Set(c.SecretShare).Add(adjust),
		Public:      c.Public.Add(adjustG),
	}, nil
}

// DeriveChild adjusts the shares to represent the derived public key at a certain index.
//
// This will panic if the group is not curve.Secp256k1
//
// This derivation works according to BIP-32, see:
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func (c *ConfigSender) DeriveBIP32(i uint32) (*ConfigSender, error) {
	publicKey, ok := c.Public.(*curve.Secp256k1Point)
	if !ok {
		return nil, errors.New("DeriveChild called on non secp256k1 curve")
	}
	scalar, newChainKey, err := bip32.DeriveScalar(publicKey, c.ChainKey, i)
	if err != nil {
		return nil, err
	}
	return c.Derive(scalar, newChainKey)
}
