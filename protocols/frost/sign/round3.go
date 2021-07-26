package sign

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

type round3 struct {
	*round2
	// rho contains the binding values for each party.
	//
	// rho[l] corresponds to rho_l in Figure 3.
	rho map[party.ID]*curve.Scalar
	// R is the group commitment, and the first part of the consortium signature
	R *curve.Point
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
