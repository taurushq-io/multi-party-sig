package xor

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/types"
)

// Round2 embeds Round1 so that it has access to previous information.
type Round2 struct {
	// received holds all xor values received from other parties
	received map[party.ID][]byte
	*Round1
}

// Round2Message is the message sent in Round1 and received in Round2.
type Round2Message struct {
	XOR []byte
}

// VerifyMessage casts the content to the appropriate type and stores the content.
func (r *Round2) VerifyMessage(from party.ID, to party.ID, content message.Content) error {
	body, ok := content.(*Round2Message)
	if !ok || body == nil {
		return message.ErrInvalidContent
	}

	if len(body.XOR) != 32 {
		return errors.New("xor should be 32 bytes long")
	}
	return nil
}

// StoreMessage saves any relevant data from the content, in this case the sender's xor value.
func (r *Round2) StoreMessage(from party.ID, content message.Content) error {
	body := content.(*Round2Message)
	// store the received value
	r.received[from] = body.XOR
	return nil
}

// Finalize does not send any messages, but computes the output resulting from the received messages.
func (r *Round2) Finalize(chan<- *message.Message) (round.Round, error) {
	resultXOR := make([]byte, 32)
	for _, received := range r.received {
		for i := range resultXOR {
			resultXOR[i] ^= received[i]
		}
	}
	return &round.Output{Result: Result(resultXOR)}, nil
}

// MessageContent returns an uninitialized Round2Message used to unmarshal contents embedded in message.Message.
func (r *Round2) MessageContent() message.Content { return &Round2Message{} }

// RoundNumber indicates which round this message is supposed to be received in.
func (m *Round2Message) RoundNumber() types.RoundNumber { return 2 }
