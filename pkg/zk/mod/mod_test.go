package zkmod

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cronokirby/safenum"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/zk"
)

func TestMod(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	p, q := zk.ProverPaillierSecret.P(), zk.ProverPaillierSecret.Q()
	sk := zk.ProverPaillierSecret
	public := Public{N: sk.PublicKey.N()}
	proof := NewProof(pl, hash.New(), public, Private{
		P:   p,
		Q:   q,
		Phi: sk.Phi(),
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

	proof.W = new(safenum.Nat).SetUint64(0)
	for idx := range proof.Responses {
		proof.Responses[idx].X = new(safenum.Nat).SetUint64(0)
	}

	assert.False(t, proof.Verify(pl, hash.New(), public), "proof should have failed")
}

func Test_set4thRoot(t *testing.T) {
	var p, q uint64 = 311, 331
	pMod := safenum.ModulusFromUint64(p)
	pHalf := new(safenum.Nat).SetUint64((p - 1) / 2)
	qMod := safenum.ModulusFromUint64(q)
	qHalf := new(safenum.Nat).SetUint64((q - 1) / 2)
	n := safenum.ModulusFromUint64(p * q)
	phi := new(safenum.Nat).SetUint64((p - 1) * (q - 1))
	y := new(safenum.Nat).SetUint64(502)
	w := sample.QNR(rand.Reader, n)

	a, b, x := makeQuadraticResidue(y, w, pHalf, qHalf, n, pMod, qMod)

	root := fourthRoot(x, phi, n)

	if b {
		y.ModMul(y, w, n)
	}
	if a {
		y.ModNeg(y, n)
	}

	assert.NotEqual(t, root, big.NewInt(1), "root cannot be 1")
	root.Exp(root, new(safenum.Nat).SetUint64(4), n)
	assert.True(t, root.Eq(y) == 1, "root^4 should be equal to y")
}
