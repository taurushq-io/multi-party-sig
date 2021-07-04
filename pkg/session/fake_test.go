package session

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

func TestFakeKeygen(t *testing.T) {
	N := 3
	T := 2
	sessions := FakeRefresh(N, T)

	for _, s := range sessions {
		if err := s.Validate(); err != nil {
			t.Error(err)
		}
	}
}

func TestGenerateShares(t *testing.T) {
	N := 20
	T := 5
	partyIDs := party.RandomIDs(N)

	//subPartyIDs := partyIDs[:T+1]
	shares, ecdsaSecret := generateShares(partyIDs, T)

	sum := curve.NewScalar()
	for i, pid := range partyIDs {
		//for i, pid := range subPartyIDs {
		l := partyIDs.Lagrange(pid)
		sum.MultiplyAdd(l, shares[i], sum)
	}
	assert.True(t, ecdsaSecret.Equal(sum))
}
