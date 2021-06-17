package zksch

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
)

func TestSchPass(t *testing.T) {
	x, X := sample.ScalarPointPair()
	a, A := sample.ScalarPointPair()

	proof := Prove(hash.New(), A, X, a, x)
	assert.True(t, Verify(hash.New(), A, X, proof), "failed passing test")
}
func TestSchFail(t *testing.T) {
	x, X := curve.NewScalar(), curve.NewIdentityPoint()
	a, A := sample.ScalarPointPair()

	proof := Prove(hash.New(), A, X, a, x)
	assert.False(t, Verify(hash.New(), A, X, proof))
}
