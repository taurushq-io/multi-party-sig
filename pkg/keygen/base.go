package keygen

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

type roundBase struct {
	s *session.Session
	p *Parameters
	h *hash.Hash

	selfID    party.ID
	thisParty *localParty
	parties   map[party.ID]*localParty
}

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

	h, err := session.Hash()
	if err != nil {
		return nil, fmt.Errorf("newRound: session.Hash: %w", err)
	}

	return &round1{
		roundBase: &roundBase{
			s:         session,
			p:         parameters,
			h:         h,
			selfID:    selfID,
			thisParty: parties[selfID],
			parties:   parties,
		}}, nil
}
