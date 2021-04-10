package round

import "github.com/taurusgroup/cmp-ecdsa/pkg/message"

type Round interface {
	HandleMessage(msg *message.Message) error
	ProcessRound() error
}

type Error struct {
	// Round is the round number the error occurred in
	Round int

	// Party is the culprit that caused the error.
	Party uint32

	// err
	err error
}

func (err *Error) Error() string {
	return err.err.Error()
}
