package round

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
)

// Output is an empty round containing the output of the protocol.
type Output struct {
	Result interface{}
}

func (r *Output) VerifyMessage(party.ID, party.ID, message.Content) error {
	return errors.New("result round does not accept any message")
}

func (r *Output) StoreMessage(party.ID, message.Content) error {
	return errors.New("result round does not accept any message")
}

func (r *Output) Finalize(chan<- *message.Message) (Round, error) {
	return r, errors.New("result round is already finalized")
}

func (r *Output) MessageContent() message.Content {
	return &message.Final{}
}
