package zkelog

import (
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/elgamal"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

func TestElog(t *testing.T) {
	group := curve.Secp256k1{}

	H := sample.Scalar(rand.Reader, group).ActOnBase()
	X := sample.Scalar(rand.Reader, group).ActOnBase()
	y := sample.Scalar(rand.Reader, group)
	Y := y.Act(H)

	E, lambda := elgamal.Encrypt(X, y)

	public := Public{
		E:             E,
		ElGamalPublic: X,
		Base:          H,
		Y:             Y,
	}

	proof := NewProof(group, hash.New(), public, Private{
		Y:      y,
		Lambda: lambda,
	})
	assert.True(t, proof.Verify(hash.New(), public))

	out, err := cbor.Marshal(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := Empty(group)
	require.NoError(t, cbor.Unmarshal(out, proof2), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := Empty(group)
	require.NoError(t, cbor.Unmarshal(out2, proof3), "failed to unmarshal 2nd proof")

	assert.True(t, proof3.Verify(hash.New(), public))
}
