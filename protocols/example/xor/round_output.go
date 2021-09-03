package xor

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// Round2 embeds Round1 so that it has access to previous information.
type Round2 struct {
	// received holds all xor values received from other parties
	received map[party.ID]types.RID
	*Round1
}

// Round2Message is the message sent in Round1 and received in Round2.
type Round2Message struct {
	XOR types.RID
}

// VerifyMessage casts the content to the appropriate type and stores the content.
func (r *Round2) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*Round2Message)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if len(body.XOR) != 32 {
		return errors.New("xor should be 32 bytes long")
	}
	return nil
}

// StoreMessage saves any relevant data from the content, in this case the sender's xor value.
func (r *Round2) StoreMessage(msg round.Message) error {

	from, body := msg.From, msg.Content.(*Round2Message)
	// store the received value
	r.received[from] = body.XOR
	return nil
}

// Finalize does not send any messages, but computes the output resulting from the received messages.
func (r *Round2) Finalize(chan<- *round.Message) (round.Session, error) {
	resultXOR := types.EmptyRID()
	for _, received := range r.received {
		resultXOR.XOR(received)
	}
	return r.ResultRound(Result(resultXOR)), nil
}

// RoundNumber should return the same things as Round.Number.
func (Round2Message) RoundNumber() round.Number { return 2 }

// MessageContent implements round.Round.
func (Round2) MessageContent() round.Content { return &Round2Message{} }

// Number implements round.Round.
func (Round2) Number() round.Number { return 2 }
