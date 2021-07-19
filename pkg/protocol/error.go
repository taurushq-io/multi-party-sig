package protocol

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

// Error is a custom error for protocols which contains information about the responsible round in which it occurred,
// and the party responsible.
type Error struct {
	// RoundNumber where the error occurred
	RoundNumber types.RoundNumber
	// Culprit is empty if the identity of the misbehaving party cannot be known
	Culprit party.ID
	// Err is the underlying error
	Err error
}

func (e Error) Error() string {
	if e.Culprit == "" {
		return fmt.Sprintf("round %d: %s", e.RoundNumber, e.Err)
	}
	return fmt.Sprintf("round %d: party: %s: %s", e.RoundNumber, e.Culprit, e.Err)
}

func (e Error) Unwrap() error {
	return e.Err
}

// MessageError may be returned by Round.ProcessMessage and provides information to the caller about
// what should be done with the message.
type MessageError string

const (
	ErrMessageDuplicate          MessageError = "protocol: message was already handled"
	ErrMessageUnknownSender      MessageError = "protocol: unknown sender"
	ErrMessageNilContent         MessageError = "protocol: message content is nil"
	ErrMessageWrongSSID          MessageError = "protocol: SSID mismatch"
	ErrMessageWrongProtocolID    MessageError = "protocol: wrong protocol ID"
	ErrMessageFromSelf           MessageError = "protocol: message is from Self"
	ErrMessageNotSorted          MessageError = "protocol: msg.To field is not sorted"
	ErrMessageWrongDestination   MessageError = "protocol: message is not intended for selfID"
	ErrMessageInvalidRoundNumber MessageError = "protocol: round number is invalid for this protocol"
)

// Error implements error
func (err MessageError) Error() string {
	return string(err)
}

var (
	ErrProtocolFinalRoundNotReached = errors.New("protocol: failed without error before reaching the final round")
)
