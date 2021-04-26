package keygen

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

type roundBase struct {
	session *session.Session
	c       *session.BaseConfig
	p       *Parameters

	thisParty *localParty
	parties   map[uint32]*localParty
}

func NewRound(config *session.BaseConfig, params *Parameters) (*round1, error) {
	if err := params.Verify(); err != nil {
		return nil, fmt.Errorf("newRound: config: %w", err)
	}
	params.fill()
	if !params.verify() {
		return nil, errors.New("params were not correctly generated")
	}

	c := *config

	s, err := session.New(&c)
	if err != nil {
		return nil, fmt.Errorf("newRound: config: %w", err)
	}

	parties := make(map[uint32]*localParty, c.N())
	for _, j := range c.Parties() {
		parties[j] = newParty(j)
	}

	return &round1{
		roundBase: &roundBase{
			session:   s,
			c:         &c,
			p:         params,
			thisParty: parties[c.SelfID()],
			parties:   parties,
		}}, nil
}
