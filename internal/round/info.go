package round

import (
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type Info struct {
	// ProtocolID is an identifier for this protocol
	ProtocolID string
	// FinalRoundNumber is the number of rounds before the output round.
	FinalRoundNumber Number
	// SSID the unique identifier for this protocol execution.
	SSID []byte
	// SelfID is this party's ID.
	SelfID party.ID
	// PartyIDs is a sorted slice of participating parties in this protocol.
	PartyIDs party.IDSlice
	// Group returns the group used for this protocol execution.
	Group curve.Curve
}
