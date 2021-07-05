package sign

import (
	"errors"
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

func Create(s session.Session) (round.Round, error) {
	if _, ok := s.(*session.Sign); !ok {
		return nil, errors.New("sign.Create: s must be a *session.Sign")
	}

	base, err := round.NewBaseRound(s, "sign")
	if err != nil {
		return nil, fmt.Errorf("sign.Create: %w", err)
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
		Message:   s.(*session.Sign).Message(),
	}, nil
}

func (r round1) ProtocolID() round.ProtocolID {
	return protocolID
}
