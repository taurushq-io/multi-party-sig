package sign

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

var (
	_ round.Round = (*round1)(nil)
	_ round.Round = (*round2)(nil)
	_ round.Round = (*round3)(nil)
	_ round.Round = (*round4)(nil)
	_ round.Round = (*output)(nil)
)

func NewRound(s *session.Sign) (*round1, error) {
	// Create round with a clone of the original secret
	base, err := round.NewBaseRound(s)
	if err != nil {
		return nil, fmt.Errorf("sign.NewRound: %w", err)
	}

	parties := make(map[party.ID]*LocalParty, s.N())
	for _, partyJ := range s.PartyIDs() {
		parties[partyJ] = &LocalParty{
			Public: s.Public(partyJ),
		}
	}

	return &round1{
		BaseRound: base,
		Self:      parties[base.SelfID],
		Secret:    s.Secret(),
		parties:   parties,
		Message:   s.Message(),
	}, nil
}
