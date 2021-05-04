package round

import (
	"github.com/taurusgroup/cmp-ecdsa/pb"
)

type Round interface {
	ProcessMessage(msg *pb.Message) error
	GenerateMessages() ([]*pb.Message, error)
	Finalize() (Round, error)
	MessageType() pb.MessageType
	RequiredMessageCount() int
	IsProcessed(id string) bool
}
