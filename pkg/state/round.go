package state

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/messages"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

// A Round represents the internal state of protocol from the perspective of the party.
// It only takes care of receiving proper messages addressed to the party, and can
// output messages that should be sent off.
//
// The methods ProcessMessage, GenerateMessages and  NextRound should all run in this order.
// Doing otherwise will most likely result in undefined behaviour.
//
//
// The suggested implementation of a Round based protocol is the following:
//
// type round0 struct {
//     *BaseRound
//     // other state variable for the entire protocol
// }
// func (r *round0) Reset() {}
// func (r *round0) AcceptedMessageTypes() []messages.MessageType { return []messages.MessageType{...} }
// func (r *round0) GenerateMessages() ([]*messages.Message, *Error) { ... }
// func (r *round0) NextRound() Round { return &round_N-1_{r} }
//
//
// For all defined rounds N=1,2,... :
//
// type round_N_ struct {
//     *round_N-1_
// }
// func (r *roundN) ProcessMessage(msg *messages.Message) *Error { ... }
// func (r *roundN) GenerateMessages() ([]*messages.Message, *Error) { ... }
// func (r *roundN) NextRound() Round { return &round_N-1_{r} }
//
type Round interface {
	// ProcessMessage takes a message and validates the contents.
	// It then stores the message as part of the Round's own state.
	// If an Error is returned then the protocol must abort.
	//
	// Round0 does not need to implement this function since it is inherited from BaseRound
	ProcessMessage(msg *messages.Message) *Error

	// GenerateMessages returns a slice of messages to be sent out at the end of this Round.
	// It assumes that ProcessMessage has run correctly for messages from all other parties.
	// At the end of this method, it is assumed that no more operations are needed for the round.
	// If an Error is returned then the protocol must abort.
	GenerateMessages() ([]*messages.Message, *Error)

	// NextRound returns the next round of the protocol.
	// This does not take into account an error having occurred.
	// The final round of the protocol should return nil, to indicate that the protocol is finished.
	NextRound() Round

	// The two following methods should be implemented by the Round0 struct.

	// AcceptedMessageTypes should return a slice containing the messages types the protocol accepts.
	// It is constant for all rounds and should therefore be implemented by a "base" round.
	AcceptedMessageTypes() []messages.Type

	// Reset is expected to zero out any sensitive data that may have been copied by the round.
	// It is called by State when the protocol finishes, either because of an abort or because we finish.
	// It only needs to be implemented in Round0 if all state is held there.
	Reset()

	// The following methods are implemented in BaseRound and can therefore be
	// be inherited by the Round0 struct.

	// SelfID returns the ID of the round participant
	SelfID() party.ID

	// Set returns a set containing all parties participating in the round
	Set() *party.Set
}
