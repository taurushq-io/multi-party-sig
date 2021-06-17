package round

import "github.com/gogo/protobuf/proto"

type MessageType int32

const MessageTypeInvalid MessageType = 0

type Message interface {
	proto.Message
	GetHeader() *Header
	Type() MessageType
	Validate() error
}
