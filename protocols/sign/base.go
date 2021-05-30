package sign

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

func NewRound(session *round.Session, secret *party.Secret, message []byte) (*round1, error) {
	err := session.Validate(secret)
	if err != nil {
		return nil, fmt.Errorf("newRound: config: %w", err)
	}

	parties := make(map[party.ID]*localParty, session.N())
	for j, publicJ := range session.Public {
		parties[j] = &localParty{
			Party: round.NewBaseParty(publicJ),
		}
	}

	base, err := round.NewBaseRound(session, secret)
	if err != nil {
		return nil, err
	}

	return &round1{
		BaseRound: base,
		thisParty: parties[secret.ID],
		parties:   parties,
		message:   message,
	}, nil
}
