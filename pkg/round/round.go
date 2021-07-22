package round

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

type Round interface {
	// ProcessMessage handles an incoming Message and validates it's content with regard to the protocol specification.
	ProcessMessage(from party.ID, content message.Content) error

	// Finalize is called after all messages from the parties have been processed in the current round.
	// Messages for the next round are sent out through the out channel.
	Finalize(out chan<- *message.Message) error

	// Next returns the next round, or nil to indicate that this is the final round
	Next() Round

	// MessageContent returns an uninitialized message.Content for this round.
	MessageContent() message.Content
}

type Final interface {
	Round
	Result() interface{}
}
