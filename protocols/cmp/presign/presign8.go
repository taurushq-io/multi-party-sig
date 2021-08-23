package presign

import (
	"github.com/taurusgroup/multi-party-sig/internal/round"
)

var _ round.Round = (*presign8)(nil)

type presign8 struct {
	*sign2
}

type message8 = messageSign2

// MessageContent implements round.Round.
func (presign8) MessageContent() round.Content { return &message8{} }

// Number implements round.Round.
func (presign8) Number() round.Number { return 8 }
