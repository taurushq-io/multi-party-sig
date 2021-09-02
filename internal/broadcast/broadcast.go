package broadcast

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

var (
	ErrBroadcastFailure = errors.New("broadcast: received different hashes")
	ErrDifferentContent = errors.New("broadcast: received message with different content")
)

// Broadcaster returns a byte slice which should uniquely determine the broadcast data.
type Broadcaster interface {
	BroadcastData() []byte
}

// New wraps the two subsequent rounds and enables the protocol to verify that all parties agree
// on all messages broadcast.
// This uses the echo broadcast by Goldwasser and Lindell.
// When there are only 2 parties, nothing happens since broadcast is by default reliable.
func New(nextRound round.Session, msg Broadcaster) round.Session {
	if nextRound.N() == 2 {
		return nextRound
	}
	return &Round1{
		Session:  nextRound,
		received: map[party.ID][]byte{nextRound.SelfID(): msg.BroadcastData()},
	}
}
