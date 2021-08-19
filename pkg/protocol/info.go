package protocol

import (
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// Info represents static information about a specific protocol execution.
type Info interface {
	// ProtocolID is an identifier for this protocol
	ProtocolID() string

	// FinalRoundNumber is the number of rounds before the output round.
	FinalRoundNumber() round.Number

	// SSID the unique identifier for this protocol execution
	SSID() []byte

	// SelfID is this party's ID.
	SelfID() party.ID

	// PartyIDs is a sorted slice of participating parties in this protocol.
	PartyIDs() party.IDSlice

	// OtherPartyIDs returns a sorted list of parties that does not contain SelfID
	OtherPartyIDs() party.IDSlice

	// N returns the number of participants.
	N() int

	// Group returns the group used for this protocol execution.
	Group() curve.Curve
}
