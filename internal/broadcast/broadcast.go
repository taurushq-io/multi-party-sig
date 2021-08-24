package broadcast

import (
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// Broadcaster returns a byte slice which should uniquely
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
