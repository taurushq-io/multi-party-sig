package protocol

import (
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// Error is a custom error for protocols which contains information about the responsible round in which it occurred,
// and the party responsible.
type Error struct {
	// RoundNumber where the error occurred
	RoundNumber round.Number
	// Culprit is empty if the identity of the misbehaving party cannot be known
	Culprit party.ID
	// Err is the underlying error
	Err error
}

// Error implement error.
func (e Error) Error() string {
	if e.Culprit == "" {
		return fmt.Sprintf("round %d: %s", e.RoundNumber, e.Err)
	}
	return fmt.Sprintf("round %d: party: %s: %s", e.RoundNumber, e.Culprit, e.Err)
}

// Unwrap implement errors.Wrapper.
func (e Error) Unwrap() error {
	return e.Err
}

// Error3 indicates that the message does not pass validation.
type Error3 string

const (
	ErrDuplicate          Error3 = "message was already handled"
	ErrUnknownSender      Error3 = "unknown sender"
	ErrWrongSSID          Error3 = "SSID mismatch"
	ErrWrongProtocolID    Error3 = "wrong protocol ID"
	ErrWrongDestination   Error3 = "message is not intended for selfID"
	ErrInvalidRoundNumber Error3 = "round number is invalid for this protocol"
	ErrInconsistentRound  Error3 = "given round number is inconsistent with content"
	ErrNilContent         Error3 = "content is empty"
)

// Error implements error.
func (err Error3) Error() string {
	return "message: " + string(err)
}
