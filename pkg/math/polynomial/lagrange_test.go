package polynomial

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

func TestLagrange(t *testing.T) {
	N := 10
	allIDs := party.RandomIDs(N)
	coefs := Lagrange(allIDs)
	sum := curve.NewScalar()
	for _, c := range coefs {
		sum.Add(sum, c)
	}
	assert.True(t, sum.Equal(curve.NewScalar().SetUInt32(1)))
}
