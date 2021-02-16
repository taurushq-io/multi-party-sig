package cmp

import (
	"go.dedis.ch/kyber/v3"
)

type Config struct {
	ID       int
	PartyIDs []int

	Parties map[int]*Party

	Secret *PartySecret

	PK kyber.Point
}

func NewConfig(partyIDs []int) []*Config {
	n := len(partyIDs)
	parties := make(map[int]*Party, n)
	secrets := make(map[int]*PartySecret, n)
	config := make([]*Config, n)

	PK := suite.Point().Null()
	for _, id := range partyIDs {
		p, s := NewParty(id)

		parties[id] = p
		secrets[id] = s

		PK.Add(PK, p.ECDSA)
	}

	for i, id := range partyIDs {
		config[i] = &Config{
			ID:       id,
			PartyIDs: partyIDs,
			Parties:  parties,
			Secret:   secrets[id],
			PK:       PK,
		}
	}
	return config
}
