package keygen

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

var _ round.Round = (*output)(nil)

type output struct {
	*round5
	Session *Session
	Secret  *Secret
}

// ProcessMessage implements round.Round.
//
// - verify all Schnorr proof for the new ecdsa share.
func (r *output) ProcessMessage(j party.ID, content message.Content) error {
	body := content.(*KeygenOutput)
	if !zksch.Verify(r.HashForID(j),
		r.SchnorrCommitments[j],
		r.Session.Public(j).ECDSA,
		body.Proof) {
		return ErrRoundOutputZKSch
	}
	return nil
}

// Finalize implements round.Round.
func (r *output) Finalize(chan<- *message.Message) (round.Round, error) {
	return &round.Output{Result: &Result{
		Session: r.Session,
		Secret:  r.Secret,
	}}, nil
}

// MessageContent implements round.Round.
func (r *output) MessageContent() message.Content { return &KeygenOutput{} }

// Validate implements message.Content.
func (m *KeygenOutput) Validate() error {
	if m == nil {
		return errors.New("keygen.round5: message is nil")
	}
	if m.Proof == nil {
		return errors.New("keygen.round5: sch proof is nil")
	}
	return nil
}

// RoundNumber implements message.Content.
func (m *KeygenOutput) RoundNumber() types.RoundNumber { return 6 }
