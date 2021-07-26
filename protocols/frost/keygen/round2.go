package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

// This round corresponds with steps 5 of Round 1, 1 of Round 2, Figure 1 in the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
type round2 struct {
	*round1
	// f_i is the polynomial this participant uses to share their contribution to
	// the secret
	f_i *polynomial.Polynomial
	// Phi contains the polynomial commitment for each participant, ourselves included.
	//
	// Phi[l][k] corresponds to phi_lk in the Frost paper.
	Phi map[party.ID]*polynomial.Exponent
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
