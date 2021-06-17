package round

import (
	"errors"
	"fmt"
	"sync"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

type Party struct {
	id party.ID

	Messages map[MessageType]Message
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
		Messages: map[MessageType]Message{},
		handled:  map[MessageType]bool{},
	}
}

func (p *Party) AddMessage(msg Message) error {
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
	_, ok := p.Messages[msgType]
	if ok {
		return fmt.Errorf("peer %s: %w", p.id, ErrDuplicateMessage)
	}

	p.Messages[msgType] = msg
	p.handled[msgType] = true

	return nil
}
