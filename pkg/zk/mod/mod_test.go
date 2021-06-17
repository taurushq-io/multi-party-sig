package zkmod

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
)

func TestMod(t *testing.T) {
	p, q := zk.ProverPaillierSecret.P, zk.ProverPaillierSecret.Q
	sk := zk.ProverPaillierSecret
	public := Public{N: sk.PublicKey.N}
	proof := NewProof(hash.New(), public, Private{
		P:   p,
		Q:   q,
		Phi: sk.Phi,
	})
	out, err := proof.Marshal()
	require.NoError(t, err, "failed to marshal proof")
	proof2 := &Proof{}
	require.NoError(t, proof2.Unmarshal(out), "failed to unmarshal proof")
	assert.Equal(t, proof, proof2)
	out2, err := proof2.Marshal()
	assert.Equal(t, out, out2)
	proof3 := &Proof{}
	require.NoError(t, proof3.Unmarshal(out2), "failed to marshal 2nd proof")
	assert.Equal(t, proof, proof3)

	assert.True(t, proof2.Verify(hash.New(), public))

	proof.W = big.NewInt(0)
	for idx := range *proof.X {
		(*proof.X)[idx] = big.NewInt(0)
	}

	assert.False(t, proof.Verify(hash.New(), public), "proof should have failed")
}

func Test_set4thRoot(t *testing.T) {
	var pInt, qInt int64 = 311, 331
	p := big.NewInt(311)
	q := big.NewInt(331)
	n := big.NewInt(pInt * qInt)
	phi := big.NewInt((pInt - 1) * (qInt - 1))
	y := big.NewInt(502)
	w := sample.QNR(n)

	a, b, x := makeQuadraticResidue(y, w, n, p, q)

	root := fourthRoot(x, phi, n)

	if b {
		y.Mul(y, w)
		y.Mod(y, n)
	}
	if a {
		y.Neg(y)
		y.Mod(y, n)
	}

	assert.NotEqual(t, root, big.NewInt(1), "root cannot be 1")
	root.Exp(root, big.NewInt(4), n)
	assert.Equal(t, root, y, "root^4 should be equal to y")
}
