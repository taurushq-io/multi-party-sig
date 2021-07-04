package round

import (
	"errors"
	"fmt"
	"sync"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

type Party struct {
	id party.ID

	messages map[MessageType]Message
	handled  map[MessageType]bool

	mu sync.Mutex
}

var (
	ErrWrongRecipient   = errors.New("message sent to wrong peer")
	ErrDuplicateMessage = errors.New("message already received")
)

func NewBaseParty(id party.ID) *Party {
	return &Party{
		id:       id,
		messages: map[MessageType]Message{},
		handled:  map[MessageType]bool{},
	}
}

func (p *Party) SetMessageHandled(msg Message) {
	p.mu.Lock()
	defer p.mu.Unlock()

}

// AddMessage returns the ID of the sender, or an error if the message is incorrect.
func (p *Party) AddMessag4e(msg Message) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	h := msg.GetHeader()
	if h == nil {
		return errors.New("round.Party: msg does not contain any header")
	}

	if p.id != h.From {
		return fmt.Errorf("peer %s: %w", p.id, ErrWrongRecipient)
	}
	msgType := msg.Type()
	_, ok := p.messages[msgType]
	if ok {
		return fmt.Errorf("peer %s: %w", p.id, ErrDuplicateMessage)
	}

	p.messages[msgType] = msg
	p.handled[msgType] = true

	return nil
}
