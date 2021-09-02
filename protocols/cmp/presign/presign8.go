package presign

import (
	"github.com/taurusgroup/multi-party-sig/internal/round"
)

var _ round.Round = (*presign8)(nil)

type presign8 struct {
	*sign2
}

// Number implements round.Round.
func (presign8) Number() round.Number { return 8 }
