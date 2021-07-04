package round

import "github.com/gogo/protobuf/proto"

type (
	MessageType     uint32
	MessageNumber   uint16
	MessageProtocol uint16
)

const (
	MessageTypeInvalid MessageType = 0
)

func (m MessageType) IsSameOrNext(m2 MessageType) bool {
	if m.Protocol() != m2.Protocol() {
		return false
	}
	return m >= m2
}

func (m MessageType) Number() MessageNumber {
	return MessageNumber(m)
}

func (m MessageType) Protocol() MessageProtocol {
	return MessageProtocol(m >> 16)
}

func (m MessageProtocol) Type() MessageType {
	return MessageType(m) << 16
}

type Message interface {
	proto.Message
	GetHeader() *Header
	Type() MessageType
	Validate() error
}
