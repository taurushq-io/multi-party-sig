package messages

import (
	"encoding/binary"
	"errors"
)

type MessageType uint8

var (
	ErrInvalidMessage = errors.New("invalid message")
)

const (
	MessageTypeKeyGen1 MessageType = iota
	MessageTypeKeyGen2
	MessageTypeSign1
	MessageTypeSign2
)

const HeaderLengthFromTo = 1 + 8

type Message struct {
	Type     MessageType
	From, To uint32
}

func (m *Message) MarshalBinary() ([]byte, error) {
	var header [HeaderLengthFromTo]byte
	header[0] = byte(m.Type)
	binary.BigEndian.PutUint32(header[1:5], m.From)
	binary.BigEndian.PutUint32(header[5:9], m.To)

	switch m.Type {
	case MessageTypeKeyGen1:
		if m.KeyGen1 != nil {
			var buf = make([]byte, HeaderLengthFromTo, HeaderLengthFromTo+m.KeyGen1.Size())
			copy(buf[:HeaderLengthFromTo], header[:])
			return m.KeyGen1.BytesAppend(buf[:HeaderLengthFromTo])
		}
	case MessageTypeKeyGen2:
		if m.KeyGen2 != nil {
			var buf [HeaderLengthFromTo + KeyGenSize2]byte
			copy(buf[:HeaderLengthFromTo], header[:])
			return m.KeyGen2.BytesAppend(buf[:HeaderLengthFromTo])
		}
	case MessageTypeSign1:
		if m.Sign1 != nil {
			var buf [HeaderLengthFromTo + SignSize1]byte
			copy(buf[:HeaderLengthFromTo], header[:])
			return m.Sign1.BytesAppend(buf[:HeaderLengthFromTo])
		}
	case MessageTypeSign2:
		if m.Sign2 != nil {
			var buf [HeaderLengthFromTo + SignSize2]byte
			copy(buf[:HeaderLengthFromTo], header[:])
			return m.Sign2.BytesAppend(buf[:HeaderLengthFromTo])
		}
	}

	return nil, errors.New("message does not contain any data")
}

func (m *Message) UnmarshalBinary(data []byte) error {
	msgType := MessageType(data[0])
	m.Type = msgType
	m.From = binary.BigEndian.Uint32(data[1:])
	m.To = binary.BigEndian.Uint32(data[5:])

	switch msgType {
	case MessageTypeKeyGen1:
		var keygen1 KeyGen1
		m.KeyGen1 = &keygen1
		return m.KeyGen1.UnmarshalBinary(data[HeaderLengthFromTo:])

	case MessageTypeKeyGen2:
		var keygen2 KeyGen2
		m.KeyGen2 = &keygen2
		return m.KeyGen2.UnmarshalBinary(data[HeaderLengthFromTo:])

	case MessageTypeSign1:
		var sign1 Sign1
		m.Sign1 = &sign1

		return m.Sign1.UnmarshalBinary(data[HeaderLengthFromTo:])

	case MessageTypeSign2:
		var sign2 Sign2
		m.Sign2 = &sign2

		return m.Sign2.UnmarshalBinary(data[HeaderLengthFromTo:])
	}
	return errors.New("message type not recognized")
}
