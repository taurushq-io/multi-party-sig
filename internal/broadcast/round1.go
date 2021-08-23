package broadcast

import (
	"bytes"
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

var ErrDifferentContent = errors.New("broadcast: received message with different content")

type Round1 struct {
	*round.Helper
	round.Round
	received map[party.ID][]byte
}

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

	return b.Round.VerifyMessage(msg)
}

func (b *Round1) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(Broadcaster)
	b.received[from] = body.BroadcastData()
	return b.Round.StoreMessage(msg)
}

func (b *Round1) Finalize(out chan<- *round.Message) (round.Round, error) {
	// Create a hash of all messages received
	h := b.Hash()
	for _, j := range b.PartyIDs() {
		_ = h.WriteAny(b.received[j])
	}
	EchoHash := h.Sum()

	c := make(chan *round.Message, b.N())
	nextRound, err := b.Round.Finalize(c)
	close(c)
	if err != nil {
		return b, err
	}

	for msg := range c {
		msg.Content = &Message2{
			Content:  msg.Content,
			EchoHash: EchoHash,
		}
		out <- msg
	}

	return &Round2{Round: nextRound, EchoHash: EchoHash}, nil
}
