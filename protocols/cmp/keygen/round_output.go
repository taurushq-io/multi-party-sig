package keygen

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

type output struct {
	*round5
}

// ProcessMessage implements round.Round
//
// - verify all Schnorr proof for the new ecdsa share
func (r *output) ProcessMessage(from party.ID, content message.Content) error {
	body := content.(*KeygenOutput)
	partyJ := r.Parties[from]

	if !zksch.Verify(r.HashForID(from),
		partyJ.SchnorrCommitments,
		r.newSession.Public(from).ECDSA,
		body.Proof) {
		return ErrRoundOutputZKSch
	}
	return nil
}

// GenerateMessages implements round.Round
func (r *output) GenerateMessages(out chan<- *message.Message) error {
	close(out)
	return nil
}

// Next implements round.Round
func (r *output) Next() round.Round {
	return nil
}

func (r *output) Result() interface{} {
	// This could be used to handle pre-signatures
	if r.newSession != nil && r.newSecret != nil {
		return &Result{
			Session: r.newSession,
			Secret:  r.newSecret,
		}
	}
	return nil
}

func (r *output) MessageContent() message.Content {
	return &KeygenOutput{}
}

func (m *KeygenOutput) Validate() error {
	if m == nil {
		return errors.New("keygen.round5: message is nil")
	}
	if m.Proof == nil {
		return errors.New("keygen.round5: sch proof is nil")
	}
	return nil
}

func (m *KeygenOutput) RoundNumber() types.RoundNumber {
	return 6
}
