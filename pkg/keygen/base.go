package keygen

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

func NewRound(session *session.Session, selfID party.ID, parameters *Parameters) (*round1, error) {
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

	parties := make(map[party.ID]*localParty, session.N())
	for _, j := range session.Parties() {
		parties[j] = newParty(j)
	}

	base, err := round.NewBaseRound(session, selfID)
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
