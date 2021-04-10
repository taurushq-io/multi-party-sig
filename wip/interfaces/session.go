package interfaces

import "github.com/taurusgroup/cmp-ecdsa/pb"

type Session interface {
	NumPeers() uint32
	PeerIDs() uint32
	SelfID() uint32
	Send(id uint32, msg pb.Message)
	//Broadcast(msg)
}
