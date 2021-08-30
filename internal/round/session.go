package round

import (
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type Info struct {
	// ProtocolID is an identifier for this protocol
	ProtocolID string
	// FinalRoundNumber is the number of rounds before the output round.
	FinalRoundNumber Number
	// SelfID is this party's ID.
	SelfID party.ID
	// PartyIDs is a sorted slice of participating parties in this protocol.
	PartyIDs []party.ID
	// Threshold is the maximum number of parties that are assumed to be corrupted during the execution of this protocol.
	Threshold int
	// Group returns the group used for this protocol execution.
	Group curve.Curve
}

// Session represents the current execution of a round-based protocol.
// It embeds the current round, and provides additional
type Session interface {
	// Round is the current round being executed.
	Round
	// Group returns the group used for this protocol execution.
	Group() curve.Curve
	// Hash returns a cloned hash function with the current hash state.
	Hash() *hash.Hash
	// ProtocolID is an identifier for this protocol.
	ProtocolID() string
	// FinalRoundNumber is the number of rounds before the output round.
	FinalRoundNumber() Number
	// SSID the unique identifier for this protocol execution.
	SSID() []byte
	// SelfID is this party's ID.
	SelfID() party.ID
	// PartyIDs is a sorted slice of participating parties in this protocol.
	PartyIDs() party.IDSlice
	// OtherPartyIDs returns a sorted list of parties that does not contain SelfID.
	OtherPartyIDs() party.IDSlice
	// Threshold is the maximum number of parties that are assumed to be corrupted during the execution of this protocol.
	Threshold() int
	// N returns the total number of parties participating in the protocol.
	N() int
}
