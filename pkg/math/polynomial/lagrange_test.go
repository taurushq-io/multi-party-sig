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
	coefsEven := Lagrange(allIDs)
	coefsOdd := Lagrange(allIDs[:N-1])
	sumEven := curve.NewScalar()
	sumOdd := curve.NewScalar()
	for _, c := range coefsEven {
		sumEven.Add(sumEven, c)
	}
	for _, c := range coefsOdd {
		sumOdd.Add(sumOdd, c)
	}
	assert.True(t, sumEven.Equal(curve.NewScalar().SetUInt32(1)))
	assert.True(t, sumOdd.Equal(curve.NewScalar().SetUInt32(1)))
}
