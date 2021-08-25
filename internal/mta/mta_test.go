package mta

import (
	mrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/zk"
)

func Test_newMtA(t *testing.T) {
	group := curve.Secp256k1{}

	source := mrand.New(mrand.NewSource(1))
	paillierI := zk.ProverPaillierPublic
	paillierJ := zk.VerifierPaillierPublic

	ski := zk.ProverPaillierSecret
	skj := zk.VerifierPaillierSecret
	ai, Ai := sample.ScalarPointPair(source, group)
	aj, Aj := sample.ScalarPointPair(source, group)

	bi := sample.Scalar(source, group)
	bj := sample.Scalar(source, group)

	Bi, _ := paillierI.Enc(curve.MakeInt(bi))
	Bj, _ := paillierJ.Enc(curve.MakeInt(bj))

	aibj := group.NewScalar().Set(ai).Mul(bj)
	ajbi := group.NewScalar().Set(aj).Mul(bi)
	c := group.NewScalar().Set(aibj).Add(ajbi)

	mtaI, betaI := New(curve.MakeInt(ai), Bj, ski, paillierJ)
	mtaJ, betaJ := New(curve.MakeInt(aj), Bi, skj, paillierI)

	msgForJ := mtaI.ProofAffG(group, hash.New(),
		curve.MakeInt(ai), Ai, Bj, betaI,
		ski, paillierJ, zk.Pedersen)
	msgForI := mtaJ.ProofAffG(group, hash.New(),
		curve.MakeInt(aj), Aj, Bi, betaJ,
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
	gammaS := group.NewScalar().SetNat(gamma.Mod(group.Order()))
	assert.Equal(t, c, gammaS, "a•b should be equal to α + β")

}
