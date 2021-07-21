package protocol

import (
	"sync"

	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

type queue struct {
	messages []*message.Message
	mtx      sync.Mutex
}

func (q *queue) Store(msg *message.Message) error {
	q.mtx.Lock()
	defer q.mtx.Unlock()

	for _, existingMsg := range q.messages {
		if existingMsg.From == msg.From && existingMsg.RoundNumber == msg.RoundNumber {
			return message.ErrMessageDuplicate
		}
	}

	q.messages = append(q.messages, msg)
	return nil
}

func (q *queue) Get(roundNumber types.RoundNumber) (out []*message.Message) {
	q.mtx.Lock()
	defer q.mtx.Unlock()

	newMessages := q.messages[:0]
	for _, msg := range q.messages {
		if msg.RoundNumber == roundNumber {
			out = append(out, msg)
		} else {
			newMessages = append(newMessages, msg)
		}
	}
	q.messages = newMessages
	return out
}
