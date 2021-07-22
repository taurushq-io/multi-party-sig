package message

import (
	"errors"
	"fmt"

	"github.com/gogo/protobuf/proto"
	gogo "github.com/gogo/protobuf/types"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

// First is an empty message used for completeness for the first round
type First struct {
	gogo.Any
}

func (m *First) Validate() error {
	return errors.New("message: First is not a valid message")
}

func (m *First) RoundNumber() types.RoundNumber {
	return 1
}

// Final is an empty message used returned by the final round.Output.
type Final struct {
	gogo.Any
}

func (m *Final) Validate() error {
	return errors.New("message: Last is not a valid message")
}

func (m *Final) RoundNumber() types.RoundNumber {
	return 0
}

// Content represents a message body for a specific round.
type Content interface {
	proto.Message
	Validate() error
	RoundNumber() types.RoundNumber
}

func (m *Message) UnmarshalContent(content Content) error {
	if err := gogo.UnmarshalAny(m.Content, content); err != nil {
		return err
	}
	if m.RoundNumber != content.RoundNumber() {
		return errors.New("message: given RoundNumber is inconsistent with content")
	}
	return content.Validate()
}

func (m Message) String() string {
	return fmt.Sprintf("message: round %d, from: %s, to %v, protocol: %s", m.RoundNumber, m.From, m.To, m.Protocol)
}

// Broadcast returns true if the message should be reliably broadcast to all participants in the protocol
func (m Message) Broadcast() bool {
	return len(m.To) == 0
}

func (m Message) Validate() error {
	if m.Content == nil {
		return ErrMessageNilContent
	}

	// check if message for previous round or beyond expected
	if m.RoundNumber <= 1 {
		return ErrMessageInvalidRoundNumber
	}

	ids := party.IDSlice(m.To)
	if !ids.Sorted() {
		return ErrMessageNotSorted
	}

	if ids.ContainsDuplicates() {
		return ErrMessageContainsDuplicates
	}
	return nil
}

// IsFor returns true if the message is intended for the designated party
func (m Message) IsFor(id party.ID) bool {
	if m.From == id {
		return false
	}
	if len(m.To) == 0 {
		return true
	}
	to := party.NewIDSlice(m.To)
	return to.Contains(id)
}
