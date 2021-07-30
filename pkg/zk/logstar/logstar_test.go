package zklogstar

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/internal/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
)

func TestLogStar(t *testing.T) {
	verifier := zk.Pedersen
	prover := zk.ProverPaillierPublic

	G := curve.NewIdentityPoint().ScalarBaseMult(sample.Scalar(rand.Reader))

	x := sample.IntervalL(rand.Reader)
	C, rho := prover.Enc(x)
	X := curve.NewIdentityPoint().ScalarMult(curve.NewScalarInt(x), G)
	public := Public{
		C:      C,
		X:      X,
		G:      G,
		Prover: prover,
		Aux:    verifier,
	}

	proof := NewProof(hash.New(), public, Private{
		X:   x,
		Rho: rho,
	})
	out, err := proof.Marshal()
	require.NoError(t, err, "failed to marshal proof")
	proof2 := &Proof{}
	require.NoError(t, proof2.Unmarshal(out), "failed to unmarshal proof")
	out2, err := proof2.Marshal()
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := &Proof{}
	require.NoError(t, proof3.Unmarshal(out2), "failed to unmarshal 2nd proof")

	assert.True(t, proof3.Verify(hash.New(), public))
}
