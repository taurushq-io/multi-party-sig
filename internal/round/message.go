package round

import (
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type Message struct {
	From, To  party.ID
	Broadcast bool
	Content   Content
}

// Content represents a message body for a specific round.
type Content interface {
	Init(curve curve.Curve)
}
