package protocol

import (
	"sync"

	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type roundQueue struct {
	ids      party.IDSlice
	messages map[party.ID]*Message
	out      chan *Message
	mtx      sync.Mutex
}

func (rq *roundQueue) receivedAll() bool {
	for _, id := range rq.ids {
		if _, present := rq.messages[id]; !present {
			return false
		}
	}
	return true
}

func (rq *roundQueue) GetHash() []byte {
	rq.mtx.Lock()
	defer rq.mtx.Unlock()
	if !rq.receivedAll() {
		return nil
	}
	h := hash.New()
	for _, id := range rq.ids {
		msg := rq.messages[id]
		if err := h.WriteAny(msg.Hash()); err != nil {
			return nil
		}
	}
	return h.Sum()
}

func (rq *roundQueue) Get(id party.ID) *Message {
	rq.mtx.Lock()
	defer rq.mtx.Unlock()
	return rq.messages[id]
}

func (rq *roundQueue) Store(msg *Message) *DuplicateFailure {
	rq.mtx.Lock()
	defer rq.mtx.Unlock()
	if existing, present := rq.messages[msg.From]; present {
		return &DuplicateFailure{
			Message1: existing,
			Message2: msg,
		}
	}
	rq.messages[msg.From] = msg
	rq.out <- msg
	if rq.receivedAll() {
		close(rq.out)
	}
	return nil
}

type queue struct {
	messages []*Message
	mtx      sync.Mutex
}

func (q *queue) Store(msg *Message) error {
	q.mtx.Lock()
	defer q.mtx.Unlock()

	for _, existingMsg := range q.messages {
		if existingMsg.From == msg.From && existingMsg.RoundNumber == msg.RoundNumber {
			return ErrDuplicate
		}
	}

	q.messages = append(q.messages, msg)
	return nil
}

func (q *queue) Get(roundNumber round.Number) (out []*Message) {
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
