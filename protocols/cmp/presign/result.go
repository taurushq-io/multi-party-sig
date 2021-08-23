package presign

import (
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type AbortResult struct {
	Culprits []party.ID
}
