package refresh

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
	"golang.org/x/crypto/sha3"
)

type base struct {
	session *session.Session
	c       *session.BaseConfig
	p       *Parameters

	thisParty *localParty
	parties   map[uint32]*localParty
}

func NewRound(config *session.BaseConfig, parameters *Parameters) (*round1, error) {
	if err := parameters.Verify(config); err != nil {
		return nil, err
	}
	parameters.fill(config)
	if !parameters.verify(config) {
		return nil, errors.New("parameters were not correctly generated")
	}

	c := *config

	h := sha3.NewShake256()
	for _, j := range c.Parties() {
		_, _ = h.Write(parameters.PublicSharesECDSA[j].BytesCompressed())
	}
	out := make([]byte, params.HashBytes)
	_, _ = h.Read(out)
	c.SetSSIDExtra(out)

	parties := make(map[uint32]*localParty, config.N())
	for _, j := range config.Parties() {
		parties[j] = newParty(j, parameters.PublicSharesECDSA[j])
	}

	s, err := session.New(&c)
	if err != nil {
		return nil, fmt.Errorf("newRound: config: %w", err)
	}

	return &round1{
		base: &base{
			session:   s,
			c:         &c,
			p:         parameters,
			thisParty: parties[c.SelfID()],
			parties:   parties,
		},
	}, nil
}
