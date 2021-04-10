package interfaces

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
)

type Peer struct {
	ID       uint32
	Messages map[message.Type]message.Message
}

var (
	ErrWrongRecipient   = errors.New("message sent to wrong peer")
	ErrDuplicateMessage = errors.New("message already received")
)

func (peer *Peer) AddMessage(msg message.Message) error {
	if peer.ID != msg.GetFrom() {
		return fmt.Errorf("peer %d: %w", peer.ID, ErrWrongRecipient)
	}
	t := msg.GetMessageType()
	_, ok := peer.Messages[t]
	if ok {
		return fmt.Errorf("peer %d: %w", peer.ID, ErrDuplicateMessage)
	}
	peer.Messages[t] = msg
	return nil
}
