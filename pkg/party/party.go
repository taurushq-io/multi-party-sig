package party

import (
	"errors"
	"fmt"
	"sync"

	"github.com/taurusgroup/cmp-ecdsa/pb"
)

type Base struct {
	ID       ID
	Messages map[pb.MessageType]*pb.Message
	handled  map[pb.MessageType]bool

	mu sync.Mutex
}

var (
	ErrWrongRecipient   = errors.New("message sent to wrong peer")
	ErrDuplicateMessage = errors.New("message already received")
)

func NewBaseParty(id ID) *Base {
	return &Base{
		ID:       id,
		Messages: map[pb.MessageType]*pb.Message{},
		handled:  map[pb.MessageType]bool{},
	}
}

func (p *Base) AddMessage(msg *pb.Message) error {
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

//func (p *Base) Handled(messageType pb.MessageType) bool {
//	p.mu.Lock()
//	defer p.mu.Unlock()
//
//}
