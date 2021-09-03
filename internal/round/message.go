package round

import (
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// Content represents the message, either broadcast or P2P returned by a round
// during finalization.
type Content interface {
	RoundNumber() Number
}

type Message struct {
	From, To  party.ID
	Broadcast bool
	Content   Content
}
