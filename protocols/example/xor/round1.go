package xor

import (
	"crypto/rand"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
)

// Round1 can embed round.Helper which provides useful methods handling messages.
type Round1 struct {
	*round.Helper
}

// ProcessMessage in the first round does nothing since no message have been received yet.
func (r *Round1) VerifyMessage(party.ID, party.ID, message.Content) error { return nil }
func (r *Round1) StoreMessage(party.ID, message.Content) error            { return nil }

// Finalize uses the out channel to communicate messages to other parties.
func (r *Round1) Finalize(out chan<- *message.Message) (round.Round, error) {
	xor := make([]byte, 32)
	_, _ = rand.Read(xor)
	// send the message to all other parties, and marshal it using the helper method which sets the appropriate headers.
	msg := r.MarshalMessage(&Round2Message{xor}, r.OtherPartyIDs()...)

	// use the helper function to send messages without blocking
	if err := r.SendMessage(msg, out); err != nil {
		return r, err
	}

	return &Round2{
		Round1:   r,
		received: map[party.ID][]byte{r.SelfID(): xor},
	}, nil
}

// MessageContent returns an empty message.First as a placeholder indicating that no message is expected.
func (r *Round1) MessageContent() message.Content { return &message.First{} }
