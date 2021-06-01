package keygen_old

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

func NewRound(session *round.Session, selfID party.ID, parameters *Parameters) (*round1, error) {
	if parameters == nil {
		parameters = &Parameters{}
	}
	if err := parameters.Verify(); err != nil {
		return nil, fmt.Errorf("newRound: config: %w", err)
	}
	parameters.fill()
	if !parameters.verify() {
		return nil, errors.New("params were not correctly generated")
	}

	err := session.Validate(nil)
	if err != nil {
		return nil, fmt.Errorf("newRound: session: %w", err)
	}

	newSession := session.CloneForKeygen()
	parties := make(map[party.ID]*localParty, newSession.N())
	for j, publicJ := range newSession.Public {
		// Set the public data to a clone of the current data
		parties[j] = &localParty{
			Party: round.NewBaseParty(publicJ),
		}
	}

	base, err := round.NewBaseRound(session, party.NewSecret(selfID, parameters.PrivateECDSA, nil, nil))
	if err != nil {
		return nil, err
	}

	return &round1{
		BaseRound: base,
		p:         parameters,
		thisParty: parties[selfID],
		parties:   parties,
	}, nil
}
