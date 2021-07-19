package message

import (
	"errors"
	"fmt"

	"github.com/gogo/protobuf/proto"
	any "github.com/gogo/protobuf/types"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

// First is an empty message used for completeness for the first round
type First struct {
	proto.Message
}

func (m *First) Validate() error {
	return errors.New("message: First is not a valid message")
}

func (m *First) RoundNumber() types.RoundNumber {
	return 1
}

type Content interface {
	proto.Message
	Validate() error
	RoundNumber() types.RoundNumber
}

func (m *Message) UnmarshalContent(content Content) error {
	if err := any.UnmarshalAny(m.Content, content); err != nil {
		return err
	}
	if m.RoundNumber != content.RoundNumber() {
		return errors.New("message: given RoundNumber is inconsistent with content")
	}
	return content.Validate()
}

func (m Message) String() string {
	return fmt.Sprintf("Message:\t %v -> %v \tRound: %d", m.From, m.To, m.RoundNumber)
}
