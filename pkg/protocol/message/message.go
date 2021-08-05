package message

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
	gogo "github.com/gogo/protobuf/types"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/types"
)

// First represents an empty message to be returned by Round.MessageContent() for the first round of a protocol.
type First struct {
	gogo.Any
}

// Validate always returns an error since the first round does not expect a message.
func (m *First) Validate() error {
	return ErrMessageFirstRound
}

// RoundNumber returns 1 since it is the first round.
func (m *First) RoundNumber() types.RoundNumber {
	return 1
}

// Final represents an empty message, and can be returned by the first round of a protocol.
type Final struct {
	gogo.Any
}

// Validate always returns an error since the first round does not expect a message.
func (m *Final) Validate() error {
	return ErrMessageLastRound
}

// RoundNumber returns 0 to indicate that it is the final round.
func (m *Final) RoundNumber() types.RoundNumber {
	return 0
}

// Content represents a message body for a specific round.
type Content interface {
	proto.Message
	Validate() error
	RoundNumber() types.RoundNumber
}

// UnmarshalContent expects a pointer to an uninitialized object implementing Content.
// Returns an error if the round number is inconsistent with the content.
func (m *Message) UnmarshalContent(content Content) error {
	if m.RoundNumber != content.RoundNumber() {
		return ErrMessageInconsistentRound
	}
	if err := gogo.UnmarshalAny(m.Content, content); err != nil {
		return err
	}
	return content.Validate()
}

// String implements fmt.Stringer.
func (m Message) String() string {
	return fmt.Sprintf("message: round %d, from: %s, to %v, protocol: %s", m.RoundNumber, m.From, m.To, m.Protocol)
}

// Broadcast returns true if the message should be reliably broadcast to all participants in the protocol.
func (m Message) Broadcast() bool {
	return len(m.To) == 0
}

// Validate checks that:
// - Content is not empty.
// - RoundNumber is valid.
// - To is sorted and does not contain duplicates.
func (m Message) Validate() error {
	if m.Content == nil {
		return ErrMessageNilContent
	}

	// check if message for previous round or beyond expected
	if m.RoundNumber <= 1 {
		return ErrMessageInvalidRoundNumber
	}

	ids := party.IDSlice(m.To)
	if !ids.Valid() {
		return ErrMessageInvalidTo
	}
	return nil
}

// IsFor returns true if the message is intended for the designated party.
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
