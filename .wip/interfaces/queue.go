package interfaces

import (
	"context"
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
)

type Queue struct {
	chs map[pb.MessageType]chan *pb.Message
}

var (
	ErrNotAccepted            = errors.New("queue: message type not accepted")
	ErrInvalidMessage         = errors.New("queue: invalid message")
	ErrBufferFull             = errors.New("queue: message buffer is full")
	ErrMessageTypeNotExpected = errors.New("queue: message type not expected")
)

func NewQueue(numPeers uint32, msgTypes ...pb.MessageType) *Queue {
	chs := make(map[pb.MessageType]chan *pb.Message, len(msgTypes))
	for _, t := range msgTypes {
		chs[t] = make(chan *pb.Message, numPeers)
	}
	return &Queue{
		chs: chs,
	}
}

func (q *Queue) Push(msg *pb.Message) error {
	ch, ok := q.chs[msg.GetType()]
	if !ok {
		return ErrNotAccepted
	}
	if !msg.IsValid() {
		return ErrInvalidMessage
	}
	select {
	case ch <- msg:
		return nil
	default:
		return ErrBufferFull
	}
}

func (q *Queue) Pop(ctx context.Context, msgType pb.MessageType) (*pb.Message, error) {
	ch, ok := q.chs[msgType]
	if !ok {
		return nil, ErrMessageTypeNotExpected
	}

	select {
	case msg := <-ch:
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
