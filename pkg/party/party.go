package party

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
)

type Base struct {
	ID       uint32
	Messages map[pb.MessageType]message.Message
	handled  map[pb.MessageType]bool
}

var (
	ErrWrongRecipient   = errors.New("message sent to wrong peer")
	ErrDuplicateMessage = errors.New("message already received")
)

func NewBaseParty(id uint32) *Base {
	return &Base{
		ID:       id,
		Messages: map[pb.MessageType]message.Message{},
		handled:  map[pb.MessageType]bool{},
	}
}

func (p *Base) AddMessage(msg message.Message) error {
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
