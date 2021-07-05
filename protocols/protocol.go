// Package protocols is the abstraction layer with which the user of the library interacts with the underlying rounds.
// It should support
// - Relaying messages (output round.Message, input []byte)
// - Returning the resulting data (session.Session for keygen/refresh, or signature.Signature for sign)
// - Return any fatal errors that may have occurred.
// - Cache messages intended for future rounds.
// - Basic header validation (SSID, From, To, MessageID)
//
// It is inspired in part by getamis/alice, but is still a work in progress
package protocols

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

type Party struct {
	id party.ID

	messages map[round.MessageID]round.Message
	handled  map[round.MessageID]bool

	mu sync.Mutex
}

var (
	ErrWrongRecipient   = errors.New("message sent to wrong peer")
	ErrDuplicateMessage = errors.New("message already received")
)

func NewBaseParty(id party.ID) *Party {
	return &Party{
		id:       id,
		messages: map[round.MessageID]round.Message{},
		handled:  map[round.MessageID]bool{},
	}
}

func (p *Party) SetMessageHandled(msg round.Message) {
	p.mu.Lock()
	defer p.mu.Unlock()

}

// AddMessage returns the ID of the sender, or an error if the message is incorrect.
func (p *Party) AddMessage(msg round.Message) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	h := msg.GetHeader()
	if h == nil {
		return errors.New("round.Party: msg does not contain any header")
	}

	if p.id != h.From {
		return fmt.Errorf("peer %s: %w", p.id, ErrWrongRecipient)
	}
	msgType := msg.ID()
	_, ok := p.messages[msgType]
	if ok {
		return fmt.Errorf("peer %s: %w", p.id, ErrDuplicateMessage)
	}

	p.messages[msgType] = msg
	p.handled[msgType] = true

	return nil
}

type Queue struct {
	chs map[round.MessageID]chan round.Message
}

var (
	ErrNotAccepted            = errors.New("queue: message type not accepted")
	ErrInvalidMessage         = errors.New("queue: invalid message")
	ErrBufferFull             = errors.New("queue: message buffer is full")
	ErrMessageTypeNotExpected = errors.New("queue: message type not expected")
)

func NewQueue(numPeers uint32, msgTypes ...round.MessageID) *Queue {
	chs := make(map[round.MessageID]chan round.Message, len(msgTypes))
	for _, t := range msgTypes {
		chs[t] = make(chan round.Message, numPeers)
	}
	return &Queue{
		chs: chs,
	}
}

func (q *Queue) Push(msg round.Message) error {
	ch, ok := q.chs[msg.ID()]
	if !ok {
		return ErrNotAccepted
	}
	if err := msg.Validate(); err != nil {
		return fmt.Errorf("%v: %w", ErrInvalidMessage, err)
	}
	select {
	case ch <- msg:
		return nil
	default:
		return ErrBufferFull
	}
}

func (q *Queue) Pop(ctx context.Context, msgType round.MessageID) (round.Message, error) {
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

type receivedMessage struct {
	message *round.Message
	err     error
	handled bool
}

type Protocol struct {
	session      session.Session
	state        State
	currentRound round.Round
	queue        *Queue

	mtx    sync.Mutex
	cancel context.CancelFunc
}

func NewProtocol(s session.Session, initFunc round.CreateFunc) (*Protocol, error) {
	//currentRound, err := initFunc(s)
	//if err != nil {
	//	return nil, err
	//}
	//return &Protocol{
	//	session:      s,
	//	queue:        NewQueue(numPeers, msgTypes...),
	//	state:        Init,
	//	currentRound: currentRound,
	//}, nil
}

func (p *Protocol) Start() {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if p.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	go p.messageLoop(ctx)
	p.cancel = cancel
}

func (p *Protocol) Stop() {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if p.cancel == nil {
		return
	}
	p.cancel()
	p.cancel = nil
}

func (p *Protocol) setState(newState State) error {
	if p.state == Abort || p.state == Done {
		return errors.New("invalid new state")
	}

	//t.logger.Info("State changed", "old", t.state, "new", newState)
	//oldState := p.state
	p.state = newState
	//p.listener.OnStateChanged(oldState, newState)
	return nil
}

func (p *Protocol) messageLoop(ctx context.Context) {
	//var (
	//	err       error
	//	msg       round.Message
	//	nextRound round.Round
	//)
	//defer func() {
	//	if err == nil {
	//		_ = p.setState(Done)
	//	} else {
	//		_ = p.setState(Abort)
	//	}
	//	p.Stop()
	//}()

	//currentRound := p.currentRound
	//msgType := currentRound.ExpectedMessageID()
	//msgCount := 0

	//for {
	//	// 1. Pop messages
	//	// 2. Check if the message is handled before
	//	// 3. Handle the message
	//	// 4. Check if we collect enough messages
	//	// 5. If yes, finalize the handler. Otherwise, wait for the next message
	//	msg, err = p.queue.Pop(ctx, msgType)
	//	if err != nil {
	//		//t.logger.Warn("Failed to pop message", "err", err)
	//		return
	//	}
	//	fromID := msg.GetHeader().From
	//	//logger := t.logger.New("msgType", msgType, "fromId", id)
	//	if currentRound.IsProcessed(fromID) {
	//		//logger.Warn("The message is handled before")
	//		err = errors.New("message already handled")
	//		return
	//	}
	//
	//	err = currentRound.ProcessMessage(msg)
	//	if err != nil {
	//		//logger.Warn("Failed to save message", "err", err)
	//		err = fmt.Errorf("ProcessMessage: %w", err)
	//		return
	//	}
	//
	//	msgCount++
	//	if msgCount < currentRound.RequiredMessageCount() {
	//		continue
	//	}
	//
	//	nextRound, err = currentRound.Finalize()
	//	if err != nil {
	//		//logger.Warn("Failed to go to next handler", "err", err)
	//		err = fmt.Errorf("Finalize: %w", err)
	//		return
	//	}
	//	// if nextHandler is nil, it means we got the final result
	//	if _, ok := nextRound.(round.FinalRound); ok && nextRound == nil {
	//		return
	//	}
	//	p.currentRound = nextRound
	//	//logger.Info("Change handler", "oldType", msgType, "newType", newType)
	//	msgType = nextRound.ExpectedMessageID()
	//	msgCount = 0
	//}
}

func (p *Protocol) AddMessage(msg round.Message) error {
	if msg.ID().IsSameOrNext(p.currentRound.ExpectedMessageID()) {
		//t.logger.Debug("Ignore old message", "currentMsgType", currentMsgType, "newMessageType", newMessageType)
		return errors.New("message for previous round or other protocol")
	}
	return p.queue.Push(msg)
}

func (p *Protocol) State() State {
	return p.state
}
func (p *Protocol) CurrentRound() round.Round {
	return p.currentRound
}

// State is a protocol state
type State uint32

const (
	// Init is the state if the process is just created.
	Init State = 0
	// Done is the state if the process is done.
	Done State = 10
	// Abort is the state if the process is aborting
	Abort State = 20
)

func (s State) String() string {
	switch s {
	case Init:
		return "Init"
	case Done:
		return "Done"
	case Abort:
		return "Abort"
	}
	return "Unknown"
}
