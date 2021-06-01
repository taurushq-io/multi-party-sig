package zkmod

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
)

func TestMod(t *testing.T) {
	p, q := zk.ProverPaillierSecret.P, zk.ProverPaillierSecret.Q
	sk := zk.ProverPaillierSecret
	public := Public{N: sk.PublicKey().N}
	proof, err := public.Prove(hash.New(), Private{
		P:   p,
		Q:   q,
		Phi: sk.Phi,
	})
	require.NoError(t, err, "failed to create proof")
	assert.True(t, public.Verify(hash.New(), proof), "failed to verify proof")

	proof.W = pb.NewInt(big.NewInt(0))
	for idx := range proof.X {
		proof.X[idx] = pb.NewInt(big.NewInt(0))
	}

	assert.False(t, public.Verify(hash.New(), proof), "proof should have failed")
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
