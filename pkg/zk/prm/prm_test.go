package zkprm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
)

func TestMod(t *testing.T) {
	sk := paillier.NewSecretKey()
	ped, lambda := sk.GeneratePedersen()

	public := Public{
		ped,
	}

	proof := NewProof(hash.New(), public, Private{
		Lambda: lambda,
		Phi:    sk.Phi(),
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
