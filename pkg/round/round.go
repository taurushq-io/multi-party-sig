package round

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
	"github.com/taurusgroup/cmp-ecdsa/protocols/sign/signature"
)

type Round interface {
	// ProcessMessage handles an incoming Message.
	// In general, it should not modify the underlying Round, but only the sender's local state.
	// At the end, the message is stored
	ProcessMessage(msg Message) error

	// GenerateMessages returns an array of Message to be sent subsequently.
	// If an error has been detected, then no messages are returned.
	GenerateMessages() ([]Message, error)

	// Next returns the next round.
	Next() Round

	// MessageContent returns an uninitialized message.Content for this round
	MessageContent() Content
}

type Final interface {
	Round
	Result() interface{}
}
