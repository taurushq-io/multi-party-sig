package refresh

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

var (
	_ round.Round = (*round1)(nil)
	_ round.Round = (*round2)(nil)
	_ round.Round = (*round3)(nil)
	_ round.Round = (*round4)(nil)
	_ round.Round = (*output)(nil)
)

func NewRound(session *round.Session) (*round1, error) {
	if !session.KeygenDone() {
		return nil, errors.New("refresh.NewRound: session has no keygen data")
	}

	// clone the session so we don't overwrite anything
	s := session.Clone()

	// Create round with a clone of the original secret
	base, err := round.NewBaseRound(s)
	if err != nil {
		return nil, fmt.Errorf("refresh.NewRound: %w", err)
	}

	parties := make(map[party.ID]*localParty, s.N())
	for j, publicJ := range s.Public {
		// Set the public data to a clone of the current data
		parties[j] = &localParty{
			Party: round.NewBaseParty(publicJ),
		}
	}

	return &round1{
		BaseRound: base,
		keygen:    !s.KeygenDone(),
		thisParty: parties[base.SelfID],
		parties:   parties,
	}, nil
}
