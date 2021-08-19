package broadcast

import (
	"bytes"

	"github.com/taurusgroup/multi-party-sig/internal/round"
)

type round2 struct {
	round.Round
	EchoHash []byte
}

type message2 struct {
	round.Content

	// EchoHash is a hash of all previous hashes of broadcast data.
	// May be empty when no data was broadcast in the previous round.
	EchoHash []byte
}

func (b *round2) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if !bytes.Equal(body.EchoHash, b.EchoHash) {
		panic("fs")
	}
	return b.Round.VerifyMessage(round.Message{
		From:    msg.From,
		To:      msg.To,
		Content: body.Content,
	})
}

func (b *round2) StoreMessage(msg round.Message) error {
	body := msg.Content.(*message2)
	return b.Round.StoreMessage(round.Message{
		From:    msg.From,
		To:      msg.To,
		Content: body.Content,
	})
}

func (b *round2) MessageContent() round.Content {
	return &message2{
		Content: b.Round.MessageContent(),
	}
}
