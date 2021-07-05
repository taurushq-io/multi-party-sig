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

	// Finalize performs
	Finalize() (Round, error)

	// ExpectedMessageID returns the expected MessageID for the current round.
	ExpectedMessageID() MessageID

	// Number returns the round's number in the protocol
	Number() int

	// ProtocolName returns a string representing the protocol
	ProtocolName() string

	ProtocolID() ProtocolID
}

type FinalRound interface {
	Round
	GetSignature() (*signature.Signature, error)
	GetSession() (session.Session, error)
}
