package zkdec

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/zk"
)

func TestDec(t *testing.T) {
	verifierPedersen := zk.Pedersen
	prover := zk.ProverPaillierPublic

	y := sample.IntervalL(rand.Reader)
	x := curve.NewScalarInt(y)

	C, rho := prover.Enc(y)

	public := Public{
		C:      C,
		X:      x,
		Prover: prover,
		Aux:    verifierPedersen,
	}
	private := Private{
		Y:   y,
		Rho: rho,
	}

	proof := NewProof(hash.New(), public, private)
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
