package round

import (
	"github.com/taurusgroup/cmp-ecdsa/pb"
)

type Round interface {
	// ProcessMessage handles an incoming pb.Message.
	// In general, it should not modify the underlying Round, but only the sender's local state.
	// At the end, the message is stored
	ProcessMessage(msg *pb.Message) error
	GenerateMessages() ([]*pb.Message, error)
	Finalize() (Round, error)
	MessageType() pb.MessageType
	//RequiredMessageCount() int
	//IsProcessed(id string) bool
}
