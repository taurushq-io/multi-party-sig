package round

import (
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type Content interface{}

type Message struct {
	From, To  party.ID
	Broadcast bool
	Content   Content
}
