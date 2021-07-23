package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

// This round corresponds with the steps 1-4 of Round 1, Figure 1 in the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
type round1 struct {
	*round.Helper

	// threshold is the integer t which defines the maximum number of corruptions tolerated for this session.
	//
	// Alternatively, the degree of the polynomial used to share the secret.
	//
	// Alternatively, t + 1 participants are needed to make a signature.
	threshold int
}

// ProcessMessage implements round.Round.
//
// Since this is the start of the protocol, we aren't expecting to have received
// any messages yet, so we do nothing.
func (r *round1) ProcessMessage(party.ID, message.Content) error { return nil }

// Finalize implements round.Round.
func (r *round1) Finalize(out chan<- *message.Message) (round.Round, error) {
	panic("unimplemented")
}

// MessageContent implements round.Round.
//
// Since this is the first round of the protocol, we expect to see a dummy First type.
func (r *round1) MessageContent() message.Content {
	return &message.First{}
}
