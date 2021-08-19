package broadcast

import (
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type Broadcaster interface {
	BroadcastData() []byte
}

func New(helper *round.Helper, nextRound round.Round, msg Broadcaster) round.Round {
	if helper.N() == 2 {
		return nextRound
	}
	return &round1{
		Helper:   helper,
		Round:    nextRound,
		received: map[party.ID][]byte{helper.SelfID(): msg.BroadcastData()},
	}
}
