package sign

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/protocols/cmp/keygen"
)

// StartSign initiates the protocol for producing a threshold signature, with Frost.
//
// result is the result of the key generation phase, for this participant.
//
// signers is the list of all participants generating a signature together, including
// this participant.
//
// messageHash is the hash of the message a signature should be generated for.
func StartSign(result *keygen.Result, signers []party.ID, messageHash []byte) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		panic("unimplemented")
	}
}
