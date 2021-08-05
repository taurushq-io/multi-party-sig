package zksch

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

func TestSchPass(t *testing.T) {
	a := NewRandomness(rand.Reader)
	x, X := sample.ScalarPointPair(rand.Reader)

	proof := a.Prove(hash.New(), X, x)
	assert.True(t, proof.Verify(hash.New(), X, a.Commitment()), "failed passing test")
}
func TestSchFail(t *testing.T) {
	a := NewRandomness(rand.Reader)
	x, X := curve.NewScalar(), curve.NewIdentityPoint()

	proof := a.Prove(hash.New(), X, x)
	assert.False(t, proof.Verify(hash.New(), X, a.Commitment()), "proof should not accept identity point")
}
