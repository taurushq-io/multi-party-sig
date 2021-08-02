package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/taproot"
)

// Result contains all the information produced after key generation, from the perspective
// of a single participant.
type Result struct {
	// ID is the identifier for this participant.
	ID party.ID
	// Threshold is the number of accepted corruptions while still being able to sign.
	Threshold int
	// PrivateShare is the fraction of the secret key owned by this participant.
	PrivateShare *curve.Scalar
	// PublicKey is the shared public key for this consortium of signers.
	//
	// This key can be used to verify signatures produced by the consortium.
	PublicKey *curve.Point
	// ChainKey is the additional randomness we've agreed upon.
	//
	// This is only ever useful if you do BIP-32 key derivation, or something similar.
	ChainKey []byte
	// VerificationShares is a map between parties and a commitment to their private share.
	//
	// This will later be used to verify the integrity of the signing protocol.
	VerificationShares map[party.ID]*curve.Point
}

// TaprootResult is like result, but for Taproot / BIP-340 keys.
//
// The main difference is that our public key is an actual taproot public key.
type TaprootResult struct {
	// ID is the identifier for this participant.
	ID party.ID
	// Threshold is the number of accepted corruptions while still being able to sign.
	Threshold int
	// PrivateShare is the fraction of the secret key owned by this participant.
	PrivateShare *curve.Scalar
	// PublicKey is the shared public key for this consortium of signers.
	//
	// This key can be used to verify signatures produced by the consortium.
	PublicKey taproot.PublicKey
	// ChainKey is the additional randomness we've agreed upon.
	//
	// This is only ever useful if you do BIP-32 key derivation, or something similar.
	ChainKey []byte
	// VerificationShares is a map between parties and a commitment to their private share.
	//
	// This will later be used to verify the integrity of the signing protocol.
	VerificationShares map[party.ID]*curve.Point
}
