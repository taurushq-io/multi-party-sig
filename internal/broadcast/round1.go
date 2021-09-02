package broadcast

import (
	"bytes"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// Round1 simply stores the hash of all broadcast messages received.
type Round1 struct {
	round.Session
	received map[party.ID][]byte
}

// VerifyMessage checks that the msg's broadcast content matches the data we have stored.
// Since we expect only distinct message, we can return an error here if a future message
// (relayed by a peer when trying to find the culprit) does not match the one we already
// have.
func (b *Round1) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(Broadcaster)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if received := b.received[msg.From]; received != nil {
		if !bytes.Equal(received, body.BroadcastData()) {
			return ErrDifferentContent
		}
	}

	return b.Session.VerifyMessage(msg)
}

func (b *Round1) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(Broadcaster)
	b.received[from] = body.BroadcastData()
	return b.Session.StoreMessage(msg)
}

// Finalize adds the hash of all broadcast messages to the message sent in the next round.
func (b *Round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Create a hash of all messages received
	h := b.Hash()
	for _, j := range b.PartyIDs() {
		_ = h.WriteAny(b.received[j])
	}
	EchoHash := h.Sum()

	// get all messages from the underlying round.
	c := make(chan *round.Message, b.N()+1)
	nextRound, err := b.Session.Finalize(c)
	close(c)
	if err != nil {
		return b, err
	}

	// wrap the message with one containing the echo hash
	for msg := range c {
		msg.Content = &Message2{
			Content:  msg.Content,
			EchoHash: EchoHash,
		}
		out <- msg
	}

	return &Round2{Session: nextRound, EchoHash: EchoHash}, nil
}
