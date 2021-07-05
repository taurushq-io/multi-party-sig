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

// Finalize implements round.Round
func (r *output) Finalize() (round.Round, error) {
	return nil, nil
}

func (r *output) ExpectedMessageID() round.MessageID {
	return MessageTypeRefresh5
}

func (r *output) GetSignature() (*signature.Signature, error) {
	return nil, errors.New("refresh.output: protocol does not produce signatures")
}

func (r *output) GetSession() (session.Session, error) {
	// This could be used to handle pre-signatures
	if r.newSession != nil {
		return r.newSession, nil
	}
	return nil, errors.New("refresh.output: session was nil")
}
