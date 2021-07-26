package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
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
}
