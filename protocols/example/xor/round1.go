package xor

import (
	gogo "github.com/gogo/protobuf/types"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

// Round1 can embed round.Helper which provides useful methods handling messages.
type Round1 struct {
	*round.Helper
	// received holds the
	received map[party.ID][]byte
}

// ProcessMessage in the first round does nothing since no message have been received yet.
func (r *Round1) ProcessMessage(party.ID, message.Content) error { return nil }

// Finalize uses the out channel to communicate messages to other parties
func (r *Round1) Finalize(out chan<- *message.Message) error {
	// send the message to all other parties, and marshal it using the helper method which sets the appropriate headers.
	msg := r.MarshalMessage(&Round2Message{gogo.BytesValue{Value: r.received[r.SelfID()]}}, r.OtherPartyIDs()...)

	// use the helper function to send messages without blocking
	if err := r.SendMessage(msg, out); err != nil {
		return err
	}

	return nil
}

// Next returns the next round with the current round embedded
func (r *Round1) Next() round.Round { return &Round2{Round1: r} }

// MessageContent returns an empty message.First as a placeholder indicating that no message is expected
func (r *Round1) MessageContent() message.Content { return &message.First{} }
