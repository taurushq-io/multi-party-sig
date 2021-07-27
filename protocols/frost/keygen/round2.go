package keygen

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
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

// ProcessMessage implements round.Round.
func (r *round2) ProcessMessage(l party.ID, content message.Content) error {
	msg, ok := content.(*Keygen2)
	if !ok {
		return fmt.Errorf("failed to convert message to Keygen2: %v", msg)
	}

	// These steps come from Figure 1, Round 1 of the Frost paper

	// 5. "Upon receiving Phi_l, sigma_l from participants 1 <= l <= n, participant
	// P_i verifies sigma_l = (R_l, mu_l), aborting on failure, by checking
	// R_l = mu_l * G - c_l * phi_l0, where c_l = H(l, ctx, phi_l0, R_l).
	//
	// Upon success, participants delete { sigma_l | 1 <= l <= n }"
	//
	// Note: I've renamed C_l to Phi_l, as in the previous round.

	// To see why this is correct, compare this verification with the proof we
	// produced in the previous round. Note how we do the same hash cloning,
	// but this time with the ID of the message sender.
	if !msg.Sigma_i.Verify(r.Helper.HashForID(l), r.Phi[l].Constant()) {
		return fmt.Errorf("failed to verify Schnorr proof for party %s", l)
	}

	r.Phi[l] = msg.Phi_i

	return nil
}

func (r *round2) Finalize(out chan<- *message.Message) (round.Round, error) {
	// These steps come from Figure 1, Round 2 of the Frost paper

	// 1. "Each P_i securely sends to each other participant P_l a secret share
	// (l, f_i(l)), deleting f_i and each share afterward except for (i, f_i(i)),
	// which they keep for themselves."

	for _, l := range r.OtherPartyIDs() {
		msg := r.MarshalMessage(&Keygen3{F_li: r.f_i.Evaluate(l.Scalar())}, l)
		if err := r.SendMessage(msg, out); err != nil {
			return r, err
		}
	}

	shareFrom := make(map[party.ID]*curve.Scalar)
	shareFrom[r.SelfID()] = r.f_i.Evaluate(r.SelfID().Scalar())
	return &round3{round2: r, shareFrom: shareFrom}, nil
}

// MessageContent implements round.Round.
//
// Since this is the first round of the protocol, we expect to see a dummy First type.
func (r *round2) MessageContent() message.Content {
	return &Keygen2{}
}

// Validate implements message.Content
func (m *Keygen2) Validate() error {
	if m == nil {
		return errors.New("keygen.round2: message is nil")
	}
	if m.Sigma_i == nil || m.Phi_i == nil {
		return errors.New("keygen.round2: a message field is nil")
	}
	return nil
}

// RoundNumber implements message.Content
func (m *Keygen2) RoundNumber() types.RoundNumber { return 2 }
