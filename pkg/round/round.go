package round

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

type Round interface {
	// ProcessMessage handles an incoming Message and validates it's content with regard to the protocol specification.
	ProcessMessage(j party.ID, content message.Content) error

	// Finalize is called after all messages from the parties have been processed in the current round.
	// Messages for the next round are sent out through the out channel.
	Finalize(out chan<- *message.Message) (Round, error)

	// MessageContent returns an uninitialized message.Content for this round.
	MessageContent() message.Content
}

type Final interface {
	Round
	Result() interface{}
}
