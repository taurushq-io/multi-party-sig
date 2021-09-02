package mta

import (
	mrand "math/rand"
	"testing"

	"github.com/cronokirby/safenum"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/zk"
	zkaffg "github.com/taurusgroup/multi-party-sig/pkg/zk/affg"
	zkaffp "github.com/taurusgroup/multi-party-sig/pkg/zk/affp"
)

func Test_newMtA(t *testing.T) {
	group := curve.Secp256k1{}

	source := mrand.New(mrand.NewSource(1))
	paillierI := zk.ProverPaillierPublic
	paillierJ := zk.VerifierPaillierPublic

	ski := zk.ProverPaillierSecret
	skj := zk.VerifierPaillierSecret
	aiScalar := sample.Scalar(source, group)
	ajScalar := sample.Scalar(source, group)
	ai := curve.MakeInt(aiScalar)
	aj := curve.MakeInt(ajScalar)

	bi := sample.Scalar(source, group)
	bj := sample.Scalar(source, group)

	Bi, _ := paillierI.Enc(curve.MakeInt(bi))
	Bj, _ := paillierJ.Enc(curve.MakeInt(bj))

	aibj := group.NewScalar().Set(aiScalar).Mul(bj)
	ajbi := group.NewScalar().Set(ajScalar).Mul(bi)
	c := group.NewScalar().Set(aibj).Add(ajbi)

	verifyMtA := func(Di, Dj *paillier.Ciphertext, betaI, betaJ *safenum.Int) {
		alphaI, err := ski.Dec(Dj)
		require.NoError(t, err, "decryption should pass")
		alphaJ, err := skj.Dec(Di)
		require.NoError(t, err, "decryption should pass")

		gammaI := alphaI.Add(alphaI, betaI, -1)
		gammaJ := alphaJ.Add(alphaJ, betaJ, -1)
		gamma := gammaI.Add(gammaI, gammaJ, -1)
		gammaS := group.NewScalar().SetNat(gamma.Mod(group.Order()))
		assert.Equal(t, c, gammaS, "a•b should be equal to α + β")
	}

	{
		Ai, Aj := aiScalar.ActOnBase(), ajScalar.ActOnBase()
		betaI, Di, Fi, proofI := ProveAffG(group, hash.New(), ai, Ai, Bj, ski, paillierJ, zk.Pedersen)
		betaJ, Dj, Fj, proofJ := ProveAffG(group, hash.New(), aj, Aj, Bi, skj, paillierI, zk.Pedersen)

		assert.True(t, proofI.Verify(hash.New(), zkaffg.Public{
			Kv:       Bj,
			Dv:       Di,
			Fp:       Fi,
			Xp:       Ai,
			Prover:   paillierI,
			Verifier: paillierJ,
			Aux:      zk.Pedersen,
		}))
		assert.True(t, proofJ.Verify(hash.New(), zkaffg.Public{
			Kv:       Bi,
			Dv:       Dj,
			Fp:       Fj,
			Xp:       Aj,
			Prover:   paillierJ,
			Verifier: paillierI,
			Aux:      zk.Pedersen,
		}))
		verifyMtA(Di, Dj, betaI, betaJ)
	}

	{
		Ai, nonceI := ski.Enc(ai)
		Aj, nonceJ := skj.Enc(aj)
		betaI, Di, Fi, proofI := ProveAffP(group, hash.New(), ai, Ai, nonceI, Bj, ski, paillierJ, zk.Pedersen)
		betaJ, Dj, Fj, proofJ := ProveAffP(group, hash.New(), aj, Aj, nonceJ, Bi, skj, paillierI, zk.Pedersen)

		assert.True(t, proofI.Verify(group, hash.New(), zkaffp.Public{
			Kv:       Bj,
			Dv:       Di,
			Fp:       Fi,
			Xp:       Ai,
			Prover:   paillierI,
			Verifier: paillierJ,
			Aux:      zk.Pedersen,
		}))
		assert.True(t, proofJ.Verify(group, hash.New(), zkaffp.Public{
			Kv:       Bi,
			Dv:       Dj,
			Fp:       Fj,
			Xp:       Aj,
			Prover:   paillierJ,
			Verifier: paillierI,
			Aux:      zk.Pedersen,
		}))
		verifyMtA(Di, Dj, betaI, betaJ)
	}

}
