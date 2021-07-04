package interfaces

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type Protocol struct {
	numPeers     uint32
	state        State
	currentRound round.Round
	queue        *Queue

	mtx    sync.Mutex
	cancel context.CancelFunc
}

func NewProtocol(numPeers uint32, initRound round.Round, msgTypes ...round.MessageType) *Protocol {
	return &Protocol{
		numPeers:     numPeers,
		queue:        NewQueue(numPeers, msgTypes...),
		state:        Init,
		currentRound: initRound,
	}
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
	if p.state == Failed || p.state == Done {
		return errors.New("invalid new state")
	}

	//t.logger.Info("State changed", "old", t.state, "new", newState)
	//oldState := p.state
	p.state = newState
	//p.listener.OnStateChanged(oldState, newState)
	return nil
}

func (p *Protocol) messageLoop(ctx context.Context) (err error) {
	defer func() {
		if err == nil {
			_ = p.setState(Done)
		} else {
			_ = p.setState(Failed)
		}
		p.Stop()
	}()

	currentRound := p.currentRound
	msgType := currentRound.MessageType()
	msgCount := 0
	for {
		// 1. Pop messages
		// 2. Check if the message is handled before
		// 3. Handle the message
		// 4. Check if we collect enough messages
		// 5. If yes, finalize the handler. Otherwise, wait for the next message
		msg, err := p.queue.Pop(ctx, msgType)
		if err != nil {
			//t.logger.Warn("Failed to pop message", "err", err)
			return err
		}
		fromID := msg.GetFrom()
		//logger := t.logger.New("msgType", msgType, "fromId", id)
		if currentRound.IsProcessed(fromID) {
			//logger.Warn("The message is handled before")
			return errors.New("message already handled")
		}

		err = currentRound.ProcessMessage(msg)
		if err != nil round{
			//logger.Warn("Failed to save message", "err", err)
			return fmt.Errorf("ProcessMessage: %w", err)
		}

		msgCount++
		if msgCount < currentRound.RequiredMessageCount() {
			continue
		}

		nextRound, err := currentRound.Finalize()
		if err != nil {
			//logger.Warn("Failed to go to next handler", "err", err)
			return fmt.Errorf("Finalize: %w", err)
		}
		// if nextHandler is nil, it means we got the final result
		if nextRound == nil {
			return nil
		}
		p.currentRound = nextRound
		currentRound = p.currentRound
		//newType := round.MessageType()
		//logger.Info("Change handler", "oldType", msgType, "newType", newType)
		//msgType = newType
		msgCount = 0
	}
}

func (p *Protocol) AddMessage(msg *round.Message) error {
	currentMsgType := p.currentRound.MessageType()
	newMessageType := msg.GetType()
	if currentMsgType > newMessageType {
		//t.logger.Debug("Ignore old message", "currentMsgType", currentMsgType, "newMessageType", newMessageType)
		return errors.New("message for previous round")
	}
	return p.queue.Push(msg)
}

func (p *Protocol) State() State {
	return p.state
}
func (p *Protocol) CurrentRound() round.Round {
	return p.currentRound
}
