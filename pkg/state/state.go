package state

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/taurusgroup/cmp-ecdsa/pkg/messages"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

// State is a struct that manages the state for the round based protocol.
//
// It handles the initial message reception, by storing them internally and feeding them to
// the the current round when all messages have been received
type State struct {
	acceptedTypes    []messages.Type
	receivedMessages map[party.ID]*messages.Message
	queue            []*messages.Message

	timer

	roundNumber int

	round Round

	doneChan chan struct{}
	done     bool
	err      *Error

	mtx sync.Mutex
}

func NewBaseState(round Round, timeout time.Duration) (*State, error) {
	N := round.Set().N()
	s := &State{
		acceptedTypes:    append([]messages.Type{}, round.AcceptedMessageTypes()...),
		receivedMessages: make(map[party.ID]*messages.Message, N),
		queue:            make([]*messages.Message, 0, N),
		round:            round,
		doneChan:         make(chan struct{}),
	}

	s.timer = newTimer(timeout, func() {
		s.mtx.Lock()
		s.reportError(NewError(0, errors.New("message timeout")))
		s.mtx.Unlock()
	})

	for id := range round.Set().Range() {
		if id != round.SelfID() {
			s.receivedMessages[id] = nil
		}
	}

	return s, nil
}

func (s *State) wrapError(err error, culprit party.ID) error {
	if culprit == 0 {
		return fmt.Errorf("party %d, round %d: %w", s.round.SelfID(), s.roundNumber, err)
	}
	return fmt.Errorf("party %d, round %d, culprit %d: %w", s.round.SelfID(), culprit, s.roundNumber, err)
}

// HandleMessage should be called on an unmarshalled messages.Message appropriate for the protocol execution.
// It performs basic checks to see whether the message can be used.
// - Is the protocol already done
// - Is msg is valid for this round or a future one
// - Is msg for us and not from us
// - Is the sender a party in the protocol
// - Have we already received a message from the party for this round?
//
// If all these checks pass, then the message is either stored for the current round,
// or put in a queue for later rounds.
//
// Note: the properties of the messages are checked in ProcessAll.
// Therefore, the check here should be a quite fast.
func (s *State) HandleMessage(msg *messages.Message) error {
	senderID := msg.From()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.done {
		return s.wrapError(errors.New("protocol already finished"), senderID)
	}

	if len(s.acceptedTypes) == 0 {
		return s.wrapError(errors.New("no more messages being accepted"), senderID)
	}

	// Ignore messages from self
	if senderID == s.round.SelfID() {
		return nil
	}

	// Ignore message not addressed to us
	if !msg.IsBroadcast() && msg.To() != s.round.SelfID() {
		return nil
	}
	// Is the sender in our list of participants?
	if !s.round.Set().Contains(senderID) {
		return s.wrapError(errors.New("sender is not a party"), senderID)
	}

	// Check if we have already received a message from this party.
	// exists should never be false, but you never know
	if _, exists := s.receivedMessages[senderID]; exists {
		return s.wrapError(errors.New("message from this party was already received"), senderID)
	}

	if !s.isAcceptedType(msg.Type()) {
		return s.wrapError(errors.New("message type is not accepted for this type of round"), senderID)
	}

	s.ackMessage()

	if msg.Type() == s.acceptedTypes[0] {
		s.receivedMessages[senderID] = msg
	} else {
		s.queue = append(s.queue, msg)
	}

	return nil
}

// ProcessAll checks whether all messages for this round have been received.
// If so then all messages are fed to Round.ProcessMessage.
// If no error was detected, then the round is processed and new messages are generated.
// These messages are returned to the caller and should be processed.
// If all went correctly, we take the messages for the next round out of the queue,
// and move on to the next round.
func (s *State) ProcessAll() []*messages.Message {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.done {
		return nil
	}

	// Only continue if we received messages from all
	if len(s.receivedMessages) != int(s.round.Set().N()-1) {
		return nil
	}

	for _, msg := range s.receivedMessages {
		if err := s.round.ProcessMessage(msg); err != nil {
			s.reportError(err)
			return nil
		}
	}

	// remove all messages that have been processed
	for id := range s.receivedMessages {
		delete(s.receivedMessages, id)
	}

	newMessages, err := s.round.GenerateMessages()
	if err != nil {
		s.reportError(err)
		return nil
	}

	// remove the messages for the next round from the queue
	s.acceptedTypes = s.acceptedTypes[1:]
	if len(s.acceptedTypes) > 0 {
		newQueue := s.queue[:0]
		currentType := s.acceptedTypes[0]
		for _, msg := range s.queue {
			if msg.Type() == currentType {
				s.receivedMessages[msg.From()] = msg
			} else {
				newQueue = append(newQueue, msg)
			}
		}
		s.queue = newQueue
	}

	// We are finished and move on to the next round
	nextRound := s.round.NextRound()
	if nextRound == nil {
		s.finish()
	} else {
		s.roundNumber++
		s.round = nextRound
	}

	return newMessages
}

func (s *State) isAcceptedType(msgType messages.Type) bool {
	for _, otherType := range s.acceptedTypes {
		if otherType == msgType {
			return true
		}
	}
	return false
}

//
// Output
//
func (s *State) finish() {
	if s.done {
		return
	}
	s.done = true
	s.round.Reset()
	s.stopTimer()
	close(s.doneChan)
}

func (s *State) reportError(err *Error) {
	if s.done {
		return
	}
	defer s.finish()

	// We already got an error
	// TODO chain the errors
	if s.err == nil {
		err.RoundNumber = s.roundNumber
		s.err = err
	}
}

// Done should be called like context.Done:
//
// select {
//   case <-s.Done():
//   // other cases
//
func (s *State) Done() <-chan struct{} {
	return s.doneChan
}

func (s *State) Err() error {
	if s.err != nil {
		return s.err
	}
	return nil
}

// WaitForError blocks until the protocol is done.
// This happens either when the protocol has finished correctly,
// or if an error has been detected.
func (s *State) WaitForError() error {
	if !s.done {
		<-s.doneChan
	}
	return s.Err()
}

// IsFinished returns true if the protocol has aborted or successfully finished.
func (s *State) IsFinished() bool {
	return s.done
}

//
// Timeout
//

type timer struct {
	t *time.Timer
	d time.Duration
}

func newTimer(d time.Duration, f func()) timer {
	var t *time.Timer
	if d > 0 {
		t = time.AfterFunc(d, f)
	}
	return timer{
		t: t,
		d: d,
	}
}

func (t *timer) ackMessage() {
	if t.t != nil {
		t.t.Stop()
		t.t.Reset(t.d)
	}
}

func (t *timer) stopTimer() {
	if t.t != nil {
		t.t.Stop()
	}
}
