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

func New(nextRound round.Session, msg Broadcaster) round.Session {
	if nextRound.N() == 2 {
		return nextRound
	}
	return &Round1{
		Session:  nextRound,
		received: map[party.ID][]byte{nextRound.SelfID(): msg.BroadcastData()},
	}
}
