package interfaces

import "github.com/taurusgroup/cmp-ecdsa/pkg/messages"

type Round interface {
	HandleMessage(msg *messages.Message) error
	ProcessRound() error
}
