package zkencelg

import (
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/zk"
)

func TestEnc(t *testing.T) {
	group := curve.Secp256k1{}
	verifier := zk.Pedersen
	prover := zk.ProverPaillierPublic

	x := sample.IntervalL(rand.Reader)
	xScalar := group.NewScalar().SetNat(x.Mod(group.Order()))

	a := sample.Scalar(rand.Reader, group)
	b := sample.Scalar(rand.Reader, group)
	abx := group.NewScalar().Set(a).Mul(b).Add(xScalar)

	A := a.ActOnBase()
	B := b.ActOnBase()
	X := abx.ActOnBase()

	C, rho := prover.Enc(x)
	public := Public{
		C:      C,
		A:      A,
		B:      B,
		X:      X,
		Prover: prover,
		Aux:    verifier,
	}

	proof := NewProof(group, hash.New(), public, Private{
		X:   x,
		Rho: rho,
		A:   a,
		B:   b,
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
