package rounds

import (
	"errors"
	"fmt"
	"sync"

	"github.com/taurusgroup/cmp-ecdsa/pkg/messages"
)

type RoundState uint8

const (
	ProcessMessages RoundState = 1 << iota
	ProcessRound
	GenerateMessages
	NextRound

	Finished
	Abort
)

type BaseRound struct {
	selfPartyID uint32

	// AllPartyIDs is a sorted list of uint32 which represent all parties (including this one)
	// that are participating in the round
	AllPartyIDs []uint32

	// OtherPartyIDs is a set of IDs from all other parties. It is not ordered, and is mostly used to
	// iterate over the list of IDs.
	OtherPartyIDs map[uint32]struct{}

	messages *messages.Queue

	roundNumber int

	done       chan struct{}
	finalError error

	aborted bool
	state   RoundState

	mtx sync.Mutex
}

func NewBaseRound(selfPartyID uint32, allPartyIDs []uint32, acceptedTypes []messages.MessageType) (*BaseRound, error) {
	var baseRound BaseRound
	if selfPartyID == 0 {
		return nil, errors.New("selfPartyID cannot be 0")
	}
	baseRound.selfPartyID = selfPartyID

	foundSelfIDInAll := false
	finalAllPartyIDs := make([]uint32, 0, len(allPartyIDs))
	otherPartyIDs := make(map[uint32]struct{}, len(allPartyIDs))
	for _, id := range allPartyIDs {
		if id == 0 {
			return nil, errors.New("IDs in allPartyIDs cannot be 0")
		}
		if id == selfPartyID && !foundSelfIDInAll {
			finalAllPartyIDs = append(finalAllPartyIDs, id)
			foundSelfIDInAll = true
			continue
		}
		if _, ok := otherPartyIDs[id]; !ok {
			otherPartyIDs[id] = struct{}{}
			finalAllPartyIDs = append(finalAllPartyIDs, id)
		}
	}
	baseRound.OtherPartyIDs = otherPartyIDs

	if !foundSelfIDInAll {
		return nil, errors.New("selfPartyID must be included in allPartyIDs")
	}
	baseRound.AllPartyIDs = finalAllPartyIDs

	var err error
	baseRound.messages, err = messages.NewMessageQueue(selfPartyID, otherPartyIDs, acceptedTypes)
	if err != nil {
		return nil, err
	}

	baseRound.done = make(chan struct{})

	// The first round will not have ProcessMessages function, so we give the sentinel to ProcessRound
	baseRound.state = ProcessRound

	return &baseRound, nil
}

// ID is the uint32 ID of the party executing this round.
func (b *BaseRound) ID() uint32 {
	return b.selfPartyID
}

// StoreMessage takes in an unmarshalled wire message and attempts to store it in the messages.Queue.
// It returns an error depending on whether the messages.Queue was able to store it.
func (b *BaseRound) StoreMessage(message *messages.Message) error {
	return b.messages.Store(message)
}

// ProcessMessages is implemented here as an empty function so that the BaseRound and subsequent initial round
// satisfies the Round interface, even when there are no messages to process.
func (b *BaseRound) ProcessMessages() {
}

// PrepareNextRound checks whether the state of the round allows us to continue on to the next one.
// If so, then we update the round number and state, and the caller can then return the next round.
func (b *BaseRound) PrepareNextRound() bool {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	if b.state == NextRound {
		b.state = ProcessMessages
		b.roundNumber++
		return true
	}
	return false
}

func (b *BaseRound) CanProcessMessages() bool {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	return b.state == ProcessMessages && b.messages.ReceivedAll()
}

func (b *BaseRound) CanProcessRound() bool {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.state == ProcessRound
}

func (b *BaseRound) CanGenerateMessages() bool {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.state == GenerateMessages
}

func (b *BaseRound) Abort(culprit uint32, err error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	b.state = Abort
	if b.finalError == nil {
		b.finalError = fmt.Errorf("abort: party %d: %w", culprit, err)
		close(b.done)
	} else {
		b.finalError = fmt.Errorf("%v, abort: party %d: %w", b.finalError, culprit, err)
	}
}

func (b *BaseRound) Finish() {
	if b.state == Abort || b.state == Finished {
		return
	}
	b.state = Finished
	close(b.done)
}

func (b *BaseRound) NextStep() {
	switch b.state {
	case ProcessMessages:
		b.state <<= 1
		b.messages.NextRound()
	case ProcessRound, GenerateMessages:
		b.state <<= 1
	}
}

func (b *BaseRound) IsFinished() bool {
	return b.state == Finished
}

func (b *BaseRound) RoundNumber() int {
	return b.roundNumber
}

func (b *BaseRound) N() uint32 {
	return uint32(len(b.AllPartyIDs))
}

func (b *BaseRound) WaitForFinish() error {
	<-b.done
	return b.finalError
}

func (b *BaseRound) Messages() map[uint32]*messages.Message {
	return b.messages.Messages()
}
