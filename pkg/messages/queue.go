package messages

import (
	"errors"
	"sync"
)

var (
	ErrMessageTypeNotAccepted     = errors.New("message type is not accepted")
	ErrMessageFromSelf            = errors.New("message was from self")
	ErrMessageNotFromOtherParties = errors.New("sender is not a party")
	ErrWrongDestination           = errors.New("message is for other party")
)

type Queue struct {
	messages map[uint32]*Message
	queue    []*Message

	currentType   MessageType
	startingType  MessageType
	acceptedTypes []MessageType

	otherPartyIDs map[uint32]struct{}
	selfPartyID   uint32

	sync.Mutex
}

func NewMessageQueue(selfID uint32, otherPartyIDs map[uint32]struct{}, acceptedTypes []MessageType) (*Queue, error) {
	for i := range acceptedTypes {
		if i >= 1 {
			if acceptedTypes[i] == acceptedTypes[i-1] {
				return nil, errors.New("acceptedTypes contains duplicate")
			}

			if acceptedTypes[i] != acceptedTypes[i-1]+1 {
				return nil, errors.New("acceptedTypes is not in order")
			}
		}
	}

	N := len(otherPartyIDs)

	m := Queue{
		messages:      make(map[uint32]*Message, N),
		queue:         make([]*Message, 0, N*len(acceptedTypes)),
		currentType:   acceptedTypes[0],
		startingType:  acceptedTypes[0],
		acceptedTypes: acceptedTypes,
		otherPartyIDs: otherPartyIDs,
		selfPartyID:   selfID,
	}
	return &m, nil
}

func (m *Queue) Store(message *Message) error {
	m.Lock()
	defer m.Unlock()
	return m.store(message)
}

func (m *Queue) store(message *Message) error {
	// Is the message one of those we accept
	if !m.isAcceptedType(message.Type) {
		return ErrMessageTypeNotAccepted
	}

	// Is the message from someone else than us
	if message.From == m.selfPartyID {
		return ErrMessageFromSelf
	}

	// Is the sender in our list of participants?
	if _, ok := m.otherPartyIDs[message.From]; !ok {
		return ErrMessageNotFromOtherParties
	}

	// If the message has a set destination, we check that it is for us
	if message.To != 0 && message.To != m.selfPartyID {
		return ErrWrongDestination
	}

	// The message is the one we are currently accepting
	if message.Type == m.currentType {
		m.messages[message.From] = message
		return nil
	}

	// This is a future message that we store for later
	if message.Type > m.currentType {
		m.queue = append(m.queue, message)
		return nil
	}

	return nil
}

func (m *Queue) ReceivedAll() bool {
	m.Lock()
	defer m.Unlock()

	return m.receivedAll()
}

func (m *Queue) receivedAll() bool {
	m.extractFromQueue()

	if len(m.messages) == len(m.otherPartyIDs) {
		for id := range m.otherPartyIDs {
			if _, ok := m.messages[id]; !ok {
				return false
			}
		}
		return true
	}

	return false
}

func (m *Queue) NextRound() {
	m.Lock()
	defer m.Unlock()

	if !m.receivedAll() {
		return
	}

	// Delete all messages for the round
	for id := range m.messages {
		delete(m.messages, id)
	}

	// remove the current message type from the accepted list
	m.acceptedTypes = m.acceptedTypes[1:]

	if !m.isAcceptedType(m.currentType + 1) {
		return
	}

	m.currentType += 1
	m.extractFromQueue()
}

func (m *Queue) isAcceptedType(msgType MessageType) bool {
	for _, otherType := range m.acceptedTypes {
		if otherType == msgType {
			return true
		}
	}
	return false
}

func (m *Queue) Messages() map[uint32]*Message {
	m.Lock()
	defer m.Unlock()

	if m.receivedAll() {
		return m.messages
	}
	return nil
}

func (m *Queue) extractFromQueue() {
	var msg *Message
	b := m.queue[:0]
	for i := 0; i < len(m.queue); i++ {
		msg = m.queue[i]

		// msg is for the current round
		if msg.Type == m.currentType {
			if err := m.store(msg); err != nil {
				panic(err)
			}
		} else {
			b = append(b, msg)
		}
	}
	m.queue = b
}
