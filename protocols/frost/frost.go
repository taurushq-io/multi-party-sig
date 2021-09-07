package frost

import (
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/frost/keygen"
	"github.com/taurusgroup/multi-party-sig/protocols/frost/sign"
)

type (
	Config        = keygen.Config
	TaprootConfig = keygen.TaprootConfig
	Signature     = sign.Signature
)

// EmptyConfig creates an empty Config with a specific group.
//
// This needs to be called before unmarshalling, instead of just using new(Result).
// This is to allow points and scalars to be correctly unmarshalled.
func EmptyConfig(group curve.Curve) *Config {
	return &keygen.Config{
		PrivateShare:       group.NewScalar(),
		PublicKey:          group.NewPoint(),
		VerificationShares: party.EmptyPointMap(group),
	}
}

// Keygen initiates the Frost key generation protocol.
//
// This protocol establishes a new threshold signature key among a set of participants.
// Later, a subset of these participants can create signatures for this public key,
// using the private shares created in this protocol.
//
// participants is a complete set of parties that will hold a share of the secret key.
// Future signers must come from this set.
//
// threshold is the number of participants that can be corrupted without breaking
// the security of the protocol. In the future, threshold + 1 participants will need
// to cooperate to produce signatures.
//
// selfID is the identifier for the local party calling this function.
//
// This protocol corresponds to Figure 1 of the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
func Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int) protocol.StartFunc {
	return keygen.StartKeygenCommon(false, group, participants, threshold, selfID, nil, nil, nil)
}

// KeygenTaproot is like Keygen, but will make Taproot / BIP-340 compatible keys.
//
// This will also return TaprootResult instead of Result, at the end of the protocol.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#specification
func KeygenTaproot(selfID party.ID, participants []party.ID, threshold int) protocol.StartFunc {
	return keygen.StartKeygenCommon(true, curve.Secp256k1{}, participants, threshold, selfID, nil, nil, nil)
}

// Refresh
func Refresh(config *Config, participants []party.ID) protocol.StartFunc {
	return keygen.StartKeygenCommon(false, config.Curve(), participants, config.Threshold, config.ID, config.PrivateShare, config.PublicKey, config.VerificationShares.Points)
}

// RefreshTaproot is like Refresh, but will make Taproot / BIP-340 compatible keys.
//
// This will also return TaprootResult instead of Result, at the end of the protocol.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#specification
func RefreshTaproot(config *TaprootConfig, participants []party.ID) protocol.StartFunc {
	publicKey, err := curve.Secp256k1{}.LiftX(config.PublicKey)
	if err != nil {
		return func([]byte) (round.Session, error) {
			return nil, err
		}
	}
	verificationShares := make(map[party.ID]curve.Point, len(config.VerificationShares))
	for k, v := range config.VerificationShares {
		verificationShares[k] = v
	}
	return keygen.StartKeygenCommon(true, curve.Secp256k1{}, participants, config.Threshold, config.ID, config.PrivateShare, publicKey, verificationShares)
}

// Sign initiates the protocol for producing a threshold signature, with Frost.
//
// result is the result of the key generation phase, for this participant.
//
// signers is the list of all participants generating a signature together, including
// this participant.
//
// messageHash is the hash of the message a signature should be generated for.
//
// This protocol merges Figures 2 and 3 from the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
//
//
// We merge the pre-processing and signing protocols into a single signing protocol
// which doesn't require any pre-processing.
//
// Another major difference is that there's no central "Signing Authority".
// Instead, each participant independently verifies and broadcasts items as necessary.
//
// Differences stemming from this change are commented throughout the protocol.
func Sign(config *Config, signers []party.ID, messageHash []byte) protocol.StartFunc {
	return sign.StartSignCommon(false, config, signers, messageHash)
}

// SignTaproot is like Sign, but will generate a Taproot / BIP-340 compatible signature.
//
// This needs to result of a Taproot compatible key generation phase, naturally.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
func SignTaproot(config *TaprootConfig, signers []party.ID, messageHash []byte) protocol.StartFunc {
	publicKey, err := curve.Secp256k1{}.LiftX(config.PublicKey)
	if err != nil {
		return func([]byte) (round.Session, error) {
			return nil, err
		}
	}
	genericVerificationShares := make(map[party.ID]curve.Point)
	for k, v := range config.VerificationShares {
		genericVerificationShares[k] = v
	}
	normalResult := &keygen.Config{
		ID:                 config.ID,
		Threshold:          config.Threshold,
		PrivateShare:       config.PrivateShare,
		PublicKey:          publicKey,
		VerificationShares: party.NewPointMap(genericVerificationShares),
	}
	return sign.StartSignCommon(true, normalResult, signers, messageHash)
}
