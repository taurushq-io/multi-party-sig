package protocol

import (
	"fmt"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/types"
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
