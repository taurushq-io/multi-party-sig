package round

import "github.com/gogo/protobuf/proto"

type (
	MessageID     uint32
	MessageNumber uint16
)

const (
	MessageIDInvalid MessageID = 0
)

func (m MessageID) IsSameOrNext(m2 MessageID) bool {
	if m.GetProtocolID() != m2.GetProtocolID() {
		return false
	}
	return m >= m2
}

func (m MessageID) Number() MessageNumber {
	return MessageNumber(m)
}

func (m MessageID) IsProtocol(id ProtocolID) bool {
	return m.GetProtocolID() == id
}

func (m MessageID) GetProtocolID() ProtocolID {
	return ProtocolID(m >> 16)
}

type ProtocolID uint16

func (m ProtocolID) Type() MessageID {
	return MessageID(m) << 16
}

type Message interface {
	proto.Message
	GetHeader() *Header
	ID() MessageID
	Validate() error
}
