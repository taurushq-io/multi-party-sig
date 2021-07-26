package keygen

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

// This round corresponds with steps 2-4 of Round 2, Figure 1 in the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
type round3 struct {
	*round2

	// shareFrom is the secret share sent to us by a given party, including ourselves.
	//
	// shareFrom[l] corresponds to f_l(i) in the Frost paper, with i our own ID.
	shareFrom map[party.ID]*curve.Scalar
}

func (r *round3) ProcessMessage(l party.ID, content message.Content) error {
	msg, ok := content.(*Keygen3)
	if !ok {
		return fmt.Errorf("failed to convert message to Keygen3: %v", msg)
	}

	// These steps come from Figure 1, Round 2 of the Frost paper

	// 2. "Each P_i verifies their shares by calculating
	//
	//   f_l(i) * G =? sum_{k = 0}^t (i^k mod q) * phi_lk
	//
	// aborting if the check fails."

	r.shareFrom[l] = msg.F_li

	expected := curve.NewIdentityPoint().ScalarBaseMult(r.shareFrom[l])
	actual := r.Phi[l].Evaluate(r.SelfID().Scalar())
	if !expected.Equal(actual) {
		return fmt.Errorf("VSS failed to validate")
	}

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
