package zknth

import (
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/zk"
)

func TestNth(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := zk.VerifierPaillierPublic
	NMod := N.N()
	rho := sample.UnitModN(rand.Reader, NMod)
	r := N.ModulusSquared().Exp(rho, NMod.Nat())

	public := Public{N: N, R: r}
	proof := NewProof(hash.New(), public, Private{
		Rho: rho,
	})
	assert.True(t, proof.Verify(hash.New(), public))

	out, err := cbor.Marshal(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := &Proof{}
	require.NoError(t, cbor.Unmarshal(out, proof2), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := &Proof{}
	require.NoError(t, cbor.Unmarshal(out2, proof3), "failed to unmarshal 2nd proof")
	assert.True(t, proof3.Verify(hash.New(), public))
}
