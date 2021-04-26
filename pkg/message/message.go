package message

import "github.com/taurusgroup/cmp-ecdsa/pb"

type Type int32

type Message interface {
	GetFrom() uint32
	GetTo() uint32
	GetType() pb.MessageType
	IsValid() bool
	IsBroadcast() bool
}
