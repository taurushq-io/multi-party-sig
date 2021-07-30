package zkmul

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/internal/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
)

func TestMul(t *testing.T) {
	prover := zk.ProverPaillierPublic
	x := sample.IntervalL(rand.Reader)
	X, rhoX := prover.Enc(x)

	y := sample.IntervalL(rand.Reader)
	Y, _ := prover.Enc(y)

	C := Y.Clone().Mul(prover, x)
	rho := C.Randomize(prover, nil)

	public := Public{
		X:      X,
		Y:      Y,
		C:      C,
		Prover: prover,
	}
	private := Private{
		X:    x,
		Rho:  rho,
		RhoX: rhoX,
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
