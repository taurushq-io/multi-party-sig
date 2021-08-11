package zkprm

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

func TestPrm(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	sk := paillier.NewSecretKey(pl)
	ped, lambda := sk.GeneratePedersen()

	public := Public{
		ped.N(),
		ped.S(),
		ped.T(),
	}

	proof := NewProof(pl, hash.New(), public, Private{
		Lambda: lambda,
		Phi:    sk.Phi(),
		P:      sk.P(),
		Q:      sk.Q(),
	})
	assert.True(t, proof.Verify(pl, hash.New(), public))

	out, err := cbor.Marshal(proof)
	require.NoError(t, err, "failed to marshal proof")
	proof2 := &Proof{}
	require.NoError(t, cbor.Unmarshal(out, proof2), "failed to unmarshal proof")
	out2, err := cbor.Marshal(proof2)
	require.NoError(t, err, "failed to marshal 2nd proof")
	proof3 := &Proof{}
	require.NoError(t, cbor.Unmarshal(out2, proof3), "failed to unmarshal 2nd proof")

	assert.True(t, proof3.Verify(pl, hash.New(), public))
}

var p *Proof

func BenchmarkCRT(b *testing.B) {
	b.StopTimer()
	pl := pool.NewPool(0)
	defer pl.TearDown()

	sk := paillier.NewSecretKey(pl)
	ped, lambda := sk.GeneratePedersen()

	public := Public{
		ped.N(),
		ped.S(),
		ped.T(),
	}

	private := Private{
		Lambda: lambda,
		Phi:    sk.Phi(),
		P:      sk.P(),
		Q:      sk.Q(),
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		p = NewProof(nil, hash.New(), public, private)
	}
}
