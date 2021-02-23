package cmpold

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewParty(t *testing.T) {
	id := rand.Int()
	party, secret := NewParty(id)
	assert.Equal(t, id, party.ID, "party ID should be correct")
	assert.True(t, party.ECDSA.Equal(suite.Point().Mul(secret.ECDSA, nil)), "ECDSA keys should match")

}
