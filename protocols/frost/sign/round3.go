package sign

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

type round3 struct {
	*round2
}

// ProcessMessage implements round.Round.
func (r *round3) ProcessMessage(party.ID, message.Content) error { return nil }

// Finalize implements round.Round.
func (r *round3) Finalize(out chan<- *message.Message) (round.Round, error) {
	panic("unimplemented")
}

// MessageContent implements round.Round.
func (r *round3) MessageContent() message.Content {
	return &message.First{}
}

// Validate implements message.Content
func (m *Sign3) Validate() error {
	return nil
}

// RoundNumber implements message.Content
func (m *Sign3) RoundNumber() types.RoundNumber { return 3 }
