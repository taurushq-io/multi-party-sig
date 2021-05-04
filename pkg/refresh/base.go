package refresh

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

type base struct {
	s *session.Session
	p *Parameters
	h *hash.Hash

	selfID    party.ID
	selfIdx   int
	thisParty *localParty
	parties   map[party.ID]*localParty
}

func NewRound(session *session.Session, selfID party.ID, secret *session.Secret, parameters *Parameters) (*round1, error) {
	if parameters == nil {
		parameters = &Parameters{}
	}
	parameters.fill(session.Parties())
	if !parameters.verify(session.N()) {
		return nil, errors.New("parameters were not correctly generated")
	}

	err := session.Validate(secret)
	if err != nil {
		return nil, fmt.Errorf("newRound: config: %w", err)
	}

	parties := make(map[party.ID]*localParty, session.N())
	public := session.Public()
	for idx, j := range session.Parties() {
		parties[j] = newParty(j, idx, public[j].ShareECDSA())
	}

	h, err := session.Hash()
	if err != nil {
		return nil, fmt.Errorf("newRound: config: %w", err)
	}

	return &round1{
		base: &base{
			s:         session,
			p:         parameters,
			h:         h,
			selfID:    selfID,
			selfIdx:   session.Parties().GetIndex(selfID),
			thisParty: parties[selfID],
			parties:   parties,
		},
	}, nil
}
