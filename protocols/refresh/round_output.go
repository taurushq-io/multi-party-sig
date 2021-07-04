package refresh

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
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
		r.S.Public(j).ECDSA,
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

func (r *output) MessageType() round.MessageType {
	return MessageTypeRefresh5
}
