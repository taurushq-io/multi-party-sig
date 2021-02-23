package cmpold

import (
	"github.com/rs/zerolog"
)

type Round interface {
	// Store analyzes the message and determines whether it should be saved. For a future round
	// It checks to see if the message is intended for the current or future round, and that
	// this party is the correct receiver. Otherwise, the message is dropped.
	//
	// This function is blocking. A round will only process one message at a time.
	Store(message *Message) error

	// CanExecute verifies that we have received a message from every other party during this round.
	// The function is blocking.
	//
	// It is the blocking version of canExecute
	CanExecute() bool

	// GetMessagesOut runs when all messages for the current round have been received.
	// It performs the given operations, and then returns the messages to be sent to other parties
	GetMessagesOut() ([]*Message, error)

	// NextRound returns the next round and checks if the current round is finished
	NextRound() Round

	// IsFinal indicates whether we are in the signing round
	IsFinal() bool

	// Number returns the round number
	Number() int

	// Log is a logger with the current round and ID
	Log() *zerolog.Logger

	// Signature returns the full computed signature, else returns nil
	Signature() *Signature

	// SetCompletion sets the function to call when the sig is done
	SetCompletion(func())

	// Debug returns timing information
	Debug() Debug
}
