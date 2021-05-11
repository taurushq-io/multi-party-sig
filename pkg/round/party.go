package round

import (
	"errors"
	"fmt"
	"sync"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

type Party struct {
	ID party.ID

	Messages map[pb.MessageType]*pb.Message
	handled  map[pb.MessageType]bool

	mu sync.Mutex
}

var (
	ErrWrongRecipient   = errors.New("message sent to wrong peer")
	ErrDuplicateMessage = errors.New("message already received")
)

func NewBaseParty(id party.ID) *Party {
	return &Party{
		ID:       id,
		Messages: map[pb.MessageType]*pb.Message{},
		handled:  map[pb.MessageType]bool{},
	}
}

func (p *Party) AddMessage(msg *pb.Message) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ID != msg.GetFrom() {
		return fmt.Errorf("peer %d: %w", p.ID, ErrWrongRecipient)
	}
	t := msg.GetType()
	_, ok := p.Messages[t]
	if ok {
		return fmt.Errorf("peer %d: %w", p.ID, ErrDuplicateMessage)
	}

	p.Messages[t] = msg
	p.handled[t] = true

	return nil
}
