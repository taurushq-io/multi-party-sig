package message

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/types"
)

// First represents an empty message to be returned by Round.MessageContent() for the first round of a protocol.
type First struct{}

func (m *First) RoundNumber() types.RoundNumber { return 1 }

// Final represents an empty message, and can be returned by the first round of a protocol.
type Final struct{}

func (m *Final) RoundNumber() types.RoundNumber { return 0 }

// Content represents a message body for a specific round.
type Content interface {
	RoundNumber() types.RoundNumber
}

type Message struct {
	// SSID is a byte string which uniquely identifies the session this message belongs to.
	SSID []byte
	// From is the party.ID of the sender
	From party.ID
	// To is a list of intended recipients for this message.
	// If To == nil, then the message should be interpreted as a broadcast message.
	To []party.ID
	// Protocol identifies the protocol this message belongs to
	Protocol types.ProtocolID
	// RoundNumber is the index of the round this message belongs to
	RoundNumber types.RoundNumber
	// Content is the actual content consumed by the round.
	Content []byte
}

// UnmarshalContent expects a pointer to an uninitialized object implementing Content.
// Returns an error if the round number is inconsistent with the content.
func (m *Message) UnmarshalContent(content Content) error {
	if m.RoundNumber != content.RoundNumber() {
		return ErrInconsistentRound
	}
	if err := cbor.Unmarshal(m.Content, content); err != nil {
		return err
	}
	return nil
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
		return ErrNilContent
	}

	// check if message for previous round or beyond expected
	if m.RoundNumber <= 1 {
		return ErrInvalidRoundNumber
	}

	ids := party.IDSlice(m.To)
	if !ids.Valid() {
		return ErrInvalidTo
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
