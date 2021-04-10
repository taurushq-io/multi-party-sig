package interfaces

import "github.com/taurusgroup/cmp-ecdsa/pkg/message"

type Round interface {
	MessageType() message.Type
	RequiredMessageCount() uint32
	IsProcessed(id uint32) bool
	ProcessMessage(msg message.Message) error
	Finalize() (Round, error)
}
