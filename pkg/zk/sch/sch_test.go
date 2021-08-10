package zksch

import (
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

func TestSchPass(t *testing.T) {
	var group curve.Curve
	a := NewRandomness(rand.Reader, group)
	x, X := sample.ScalarPointPair(rand.Reader, group)

	proof := a.Prove(group, hash.New(), X, x)
	assert.True(t, proof.Verify(group, hash.New(), X, a.Commitment()), "failed passing test")
	assert.True(t, proof.Verify(group, hash.New(), X, a.Commitment()))

	out, err := cbor.Marshal(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := &Response{}
	require.NoError(t, cbor.Unmarshal(out, proof2), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := &Response{}
	require.NoError(t, cbor.Unmarshal(out2, proof3), "failed to unmarshal 2nd proof")

	assert.True(t, proof3.Verify(group, hash.New(), X, a.Commitment()))

}
func TestSchFail(t *testing.T) {
	var group curve.Curve
	a := NewRandomness(rand.Reader, group)
	x, X := group.NewScalar(), group.NewPoint()

	proof := a.Prove(group, hash.New(), X, x)
	assert.False(t, proof.Verify(group, hash.New(), X, a.Commitment()), "proof should not accept identity point")
}
