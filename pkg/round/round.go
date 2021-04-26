package round

import (
	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
)

type Round interface {
	ProcessMessage(msg message.Message) error
	GenerateMessages() ([]message.Message, error)
	Finalize() (Round, error)
	MessageType() pb.MessageType
	RequiredMessageCount() int
	IsProcessed(id uint32) bool
}
