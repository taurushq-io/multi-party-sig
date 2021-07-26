package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

type round3 struct {
	*round2
}

func (r *round3) ProcessMessage(l party.ID, content message.Content) error {
	return nil
}

func (r *round3) Finalize(out chan<- *message.Message) (round.Round, error) {
	panic("unimplemented")
}

// MessageContent implements round.Round.
//
// Since this is the first round of the protocol, we expect to see a dummy First type.
func (r *round3) MessageContent() message.Content {
	panic("unimplemented")
}

// Validate implements message.Content
func (m *Keygen3) Validate() error {
	return nil
}

// RoundNumber implements message.Content
func (m *Keygen3) RoundNumber() types.RoundNumber { return 3 }
