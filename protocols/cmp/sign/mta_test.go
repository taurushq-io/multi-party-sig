package sign

import (
	mrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/zk"
)

func Test_newMtA(t *testing.T) {
	source := mrand.New(mrand.NewSource(1))
	paillierI := zk.ProverPaillierPublic
	paillierJ := zk.VerifierPaillierPublic

	ski := zk.ProverPaillierSecret
	skj := zk.VerifierPaillierSecret
	ai, Ai := sample.ScalarPointPair(source)
	aj, Aj := sample.ScalarPointPair(source)

	bi := sample.Scalar(source)
	bj := sample.Scalar(source)

	Bi, _ := paillierI.Enc(bi.Int())
	Bj, _ := paillierJ.Enc(bj.Int())

	aibj := curve.NewScalar().Multiply(ai, bj)
	ajbi := curve.NewScalar().Multiply(aj, bi)
	c := curve.NewScalar().Add(aibj, ajbi)

	mtaI := NewMtA(ai, Ai, Bi, Bj, ski, paillierJ)
	mtaJ := NewMtA(aj, Aj, Bj, Bi, skj, paillierI)

	msgForJ := mtaI.ProofAffG(hash.New(), zk.Pedersen)
	msgForI := mtaJ.ProofAffG(hash.New(), zk.Pedersen)

	err := mtaI.Input(hash.New(), zk.Pedersen, msgForI, Aj)
	require.NoError(t, err, "decryption should pass")
	err = mtaJ.Input(hash.New(), zk.Pedersen, msgForJ, Ai)
	require.NoError(t, err, "decryption should pass")

	gammaI := mtaI.Share()
	gammaJ := mtaJ.Share()
	gamma := curve.NewScalar().Add(gammaI, gammaJ)
	assert.Equal(t, c, gamma, "a•b should be equal to α + β")

}
