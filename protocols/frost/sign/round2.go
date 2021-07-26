package sign

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round2 struct {
	*round1
}

// ProcessMessage implements round.Round.
func (r *round2) ProcessMessage(party.ID, message.Content) error { return nil }

// Finalize implements round.Round.
func (r *round2) Finalize(out chan<- *message.Message) (round.Round, error) {
	panic("unimplemented")
}

// MessageContent implements round.Round.
func (r *round2) MessageContent() message.Content {
	return &message.First{}
}
