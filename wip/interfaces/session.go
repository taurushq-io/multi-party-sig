package interfaces

import (
	"google.golang.org/protobuf/proto"
)

type PeerHandler interface {
	NumPeers() uint32
	PeerIDs() []uint32
	SelfID() uint32
	Send(id uint32, msg proto.Message)
	SendToAll(msg proto.Message)
	Broadcast(msg proto.Message)
}
