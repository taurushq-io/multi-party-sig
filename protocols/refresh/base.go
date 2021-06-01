package refresh

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

func NewRound(session *round.Session, secret *party.Secret, parameters *Parameters) (*round1, error) {
	// Set remaining parameters
	if parameters == nil {
		parameters = &Parameters{}
	}
	parameters.fill(session.PartyIDs())
	if !parameters.verify(session.N()) {
		return nil, errors.New("parameters were not correctly generated")
	}

	err := session.Validate(secret)
	if err != nil {
		return nil, fmt.Errorf("newRound: config: %w", err)
	}

	newSecret := &party.Secret{
		ID:    secret.ID,
		ECDSA: curve.NewScalar().Set(secret.ECDSA),
	}

	newSession := session.CloneForRefresh()

	parties := make(map[party.ID]*localParty, newSession.N())
	for j, publicJ := range newSession.Public {
		// Set the public data to a clone of the current data
		parties[j] = &localParty{
			Party: round.NewBaseParty(publicJ),
		}
	}

	// Create round with a clone of the original secret
	base, err := round.NewBaseRound(newSession, newSecret)
	if err != nil {
		return nil, err
	}

	return &round1{
		BaseRound: base,
		p:         parameters,
		thisParty: parties[newSecret.ID],
		parties:   parties,
	}, nil
}
