package sign

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
)

func Test_newMtA(t *testing.T) {
	paillierI := zk.ProverPaillierPublic
	paillierJ := zk.VerifierPaillierPublic

	ski := zk.ProverPaillierSecret
	skj := zk.VerifierPaillierSecret
	ai, Ai := sample.ScalarPointPair(rand.Reader)
	aj, Aj := sample.ScalarPointPair(rand.Reader)

	bi := sample.Scalar(rand.Reader)
	bj := sample.Scalar(rand.Reader)

	Bi, _ := paillierI.Enc(bi.Int())
	Bj, _ := paillierJ.Enc(bj.Int())

	aibj := curve.NewScalar().Multiply(ai, bj)
	ajbi := curve.NewScalar().Multiply(aj, bi)
	c := curve.NewScalar().Add(aibj, ajbi)

	mtaI := NewMtA(ai, Ai, Bi, Bj, ski, j.Paillier)
	mtaJ := NewMtA(aj, Aj, Bj, Bi, skj, i.Paillier)

	msgJ := mtaI.ProofAffG(hash.New(), j.Pedersen)
	msgI := mtaJ.ProofAffG(hash.New(), i.Pedersen)

	err := mtaI.Input(hash.New(), j.Pedersen, msgI, Aj)
	require.NoError(t, err, "decryption should pass")
	err = mtaJ.Input(hash.New(), i.Pedersen, msgJ, Ai)
	require.NoError(t, err, "decryption should pass")

	gammaI := mtaI.Share()
	gammaJ := mtaJ.Share()
	gamma := curve.NewScalar().Add(gammaI, gammaJ)
	assert.Equal(t, c, gamma, "a•b should be equal to α + β")

}
