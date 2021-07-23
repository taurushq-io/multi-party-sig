package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

type round2 struct {
	*round1
}

func (r *round2) ProcessMessage(party.ID, message.Content) error { return nil }

func (r *round2) Finalize(out chan<- *message.Message) (round.Round, error) {
	panic("unimplemented")
}

// MessageContent implements round.Round.
//
// Since this is the first round of the protocol, we expect to see a dummy First type.
func (r *round2) MessageContent() message.Content {
	panic("unimplemented")
}

// Validate implements message.Content
func (m *Keygen2) Validate() error {
	return nil
}

// RoundNumber implements message.Content
func (m *Keygen2) RoundNumber() types.RoundNumber { return 2 }
