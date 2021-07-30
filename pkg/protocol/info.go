package protocol

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol/types"
)

// Info represents static information about a specific protocol execution.
type Info interface {
	// ProtocolID is string identifier for this protocol
	ProtocolID() types.ProtocolID

	// FinalRoundNumber is the number of rounds before the output round.
	FinalRoundNumber() types.RoundNumber

	// SelfID is this party's ID.
	SelfID() party.ID

	// PartyIDs is a sorted slice of participating parties in this protocol.
	PartyIDs() party.IDSlice

	// OtherPartyIDs returns a sorted list of parties that does not contain SelfID
	OtherPartyIDs() party.IDSlice

	// SSID the unique identifier for this protocol execution
	SSID() []byte

	// N returns the number of participants.
	N() int
}
