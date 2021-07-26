package sign

import (
	fmt "fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

// This round roughly corresponds with steps 3-6 of Figure 3 in the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
//
// The main differences stem from the lack of a signature authority.
//
// This means that instead of receiving a bundle of all the commitments, instead
// each participant sends us their commitment directly.
//
// Then, instead of sending our scalar response to the authority, we broadcast it
// to everyone instead.
type round2 struct {
	*round1
	// D will contain all of the commitments created by each party, ourself included.
	D map[party.ID]*curve.Point
	// E will contain all of the commitments created by each party, ourself included.
	E map[party.ID]*curve.Point
}

// ProcessMessage implements round.Round.
func (r *round2) ProcessMessage(l party.ID, content message.Content) error {
	msg, ok := content.(*Sign2)
	if !ok {
		return fmt.Errorf("failed to convert message to Sign2: %v", msg)
	}

	// This section roughly follows Figure 3.

	// 3. "After receiving (m, B), each P_i first validates the message m,
	// and then checks D_l, E_l in G^* for each commitment in B, aborting if
	// either check fails."
	//
	// We make a few deparatures.
	//
	// We implicitly assume that the message validation has happened before
	// calling this protocol.
	//
	// We also receive each D_l, E_l from the participant l directly, instead of
	// an entire bundle from a signing authority.
	if msg.D_i.IsIdentity() || msg.E_i.IsIdentity() {
		return fmt.Errorf("nonce commitment is the identity point")
	}

	r.D[l] = msg.D_i
	r.E[l] = msg.E_i

	return nil
}

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
