package refresh

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
	"github.com/taurusgroup/cmp-ecdsa/protocols/sign/signature"
)

type output struct {
	*round5
}

// ProcessMessage implements round.Round
//
// - verify all Schnorr proof for the new ecdsa share
func (r *output) ProcessMessage(msg round.Message) error {
	j := msg.GetHeader().From
	partyJ := r.LocalParties[j]
	body := msg.(*Message).GetRefresh5()

	if !zksch.Verify(r.Hash.CloneWithID(j),
		partyJ.SchnorrCommitments,
		r.newSession.Public(j).ECDSA,
		body.Proof) {
		return fmt.Errorf("refresh.output.ProcessMessage(): party %s proof of knowledge of share failed", j)
	}

	return nil // message is properly handled
}

// GenerateMessages implements round.Round
func (r *output) GenerateMessages() ([]round.Message, error) {
	return nil, nil
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

func (r *output) MessageContent() round.Content {
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
