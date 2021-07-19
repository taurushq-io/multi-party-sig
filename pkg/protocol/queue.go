package protocol

import (
	"sync"

	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

type Queue interface {
	Store(msg *round.Message) error
	Get(roundNumber types.RoundNumber) []*round.Message
}

type queue struct {
	messages []*round.Message
	size     int
	mtx      sync.Mutex
}

func newQueue(size int) *queue {
	return &queue{
		messages: make([]*round.Message, 0, size),
		size:     size,
	}
}

func (q *queue) Store(msg *round.Message) error {
	q.mtx.Lock()
	defer q.mtx.Unlock()

	for _, existingMsg := range q.messages {
		if existingMsg.From == msg.From && existingMsg.RoundNumber == msg.RoundNumber {
			return ErrMessageDuplicate
		}
	}

	q.messages = append(q.messages, msg)
	return nil
}

func (q *queue) Get(roundNumber types.RoundNumber) []*round.Message {
	q.mtx.Lock()
	defer q.mtx.Unlock()
	outChan := make([]*round.Message, 0, q.size)
	newMessages := make([]*round.Message, 0, q.size)
	for _, msg := range q.messages {
		if msg.RoundNumber == roundNumber {
			outChan = append(outChan, msg)
		} else {
			newMessages = append(newMessages, msg)
		}
	}
	q.messages = newMessages
	return outChan
}
