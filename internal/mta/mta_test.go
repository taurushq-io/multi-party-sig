package mta

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

	mtaI, betaI := New(ai.Int(), Bj, ski, paillierJ)
	mtaJ, betaJ := New(aj.Int(), Bi, skj, paillierI)

	msgForJ := mtaI.ProofAffG(hash.New(),
		ai.Int(), Ai, Bj, betaI,
		ski, paillierJ, zk.Pedersen)
	msgForI := mtaJ.ProofAffG(hash.New(),
		aj.Int(), Aj, Bi, betaJ,
		skj, paillierI, zk.Pedersen)

	err := mtaI.VerifyAffG(hash.New(), Bi, Aj, msgForI, paillierJ, paillierI, zk.Pedersen)
	require.NoError(t, err, "decryption should pass")
	err = mtaJ.VerifyAffG(hash.New(), Bj, Ai, msgForJ, paillierI, paillierJ, zk.Pedersen)
	require.NoError(t, err, "decryption should pass")

	alphaI, err := ski.Dec(msgForI.Dij)
	require.NoError(t, err, "decryption should pass")
	alphaJ, err := skj.Dec(msgForJ.Dij)
	require.NoError(t, err, "decryption should pass")

	gammaI := alphaI.Add(alphaI, betaI, -1)
	gammaJ := alphaJ.Add(alphaJ, betaJ, -1)
	gamma := gammaI.Add(gammaI, gammaJ, -1)
	gammaS := curve.NewScalarInt(gamma)
	assert.Equal(t, c, gammaS, "a•b should be equal to α + β")

}
