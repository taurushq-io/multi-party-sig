package sign

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

type round2 struct {
	*round1
	D map[party.ID]*curve.Point
	E map[party.ID]*curve.Point
}

// ProcessMessage implements round.Round.
func (r *round2) ProcessMessage(party.ID, message.Content) error { return nil }

// Finalize implements round.Round.
func (r *round2) Finalize(out chan<- *message.Message) (round.Round, error) {
	panic("unimplemented")
}

// MessageContent implements round.Round.
func (r *round2) MessageContent() message.Content {
	return &Sign2{}
}

// Validate implements message.Content
func (m *Sign2) Validate() error {
	return nil
}

// RoundNumber implements message.Content
func (m *Sign2) RoundNumber() types.RoundNumber { return 2 }
