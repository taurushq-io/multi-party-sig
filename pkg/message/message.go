package message

type Type int32

type Message interface {
	GetFrom() uint32
	GetTo() uint32
	GetMessageType() Type
	IsValid() bool
	IsBroadcast() bool
}
