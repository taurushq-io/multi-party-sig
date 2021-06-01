package sign

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

func NewRound(session *round.Session) (*round1, error) {

	if !session.KeygenDone() {
		return nil, errors.New("sign.NewRound: session has no keygen data")
	}
	if !session.IsSigning() {
		return nil, errors.New("sign.NewRound: session is not ready for signing")
	}

	// clone the session so we don't overwrite anything
	s := session.Clone()

	// Create round with a clone of the original secret
	base, err := round.NewBaseRound(s)
	if err != nil {
		return nil, fmt.Errorf("sign.NewRound: %w", err)
	}

	parties := make(map[party.ID]*localParty, len(s.SigningParties))
	for j, publicJ := range s.SigningParties {
		parties[j] = &localParty{
			Party: round.NewBaseParty(publicJ),
		}
	}

	return &round1{
		BaseRound: base,
		thisParty: parties[base.SelfID],
		parties:   parties,
	}, nil
}
