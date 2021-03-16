package state

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

// state.Error represents an error related to the protocol execution, and requires an abort.
// If PartyID is 0, then it was not possible to attribute the fault to one particular party.
type Error struct {
	PartyID     party.ID
	RoundNumber int
	err         error
}

func NewError(partyID party.ID, err error) *Error {
	return &Error{
		PartyID: partyID,
		err:     err,
	}
}

func (e Error) Error() string {
	return fmt.Sprintf("party %d: round %d: %s", e.PartyID, e.RoundNumber, e.err.Error())
}
