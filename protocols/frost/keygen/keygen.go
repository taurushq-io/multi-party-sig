package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

// StartKeygen initiates the Frost key generation protocol.
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
func StartKeygen(participants []party.ID, threshold int, selfID party.ID) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		panic("unimplemented")
	}
}
