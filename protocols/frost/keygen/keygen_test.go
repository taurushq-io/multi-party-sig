package keygen

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func checkOutput(t *testing.T, rounds []round.Session, parties party.IDSlice) {
	group := curve.Secp256k1{}

	N := len(rounds)
	results := make([]Config, 0, N)
	for _, r := range rounds {
		resultRound, ok := r.(*round.Output)
		require.True(t, ok)
		result, ok := resultRound.Result.(*Config)
		require.True(t, ok)
		results = append(results, *result)
		require.Equal(t, r.SelfID(), result.ID)
	}

	var publicKey curve.Point
	var chainKey []byte
	privateKey := group.NewScalar()
	lagrangeCoefficients := polynomial.Lagrange(group, parties)
	for _, result := range results {
		if publicKey != nil {
			assert.True(t, publicKey.Equal(result.PublicKey), "different public key")
		}
		publicKey = result.PublicKey
		if chainKey != nil {
			assert.Equal(t, chainKey, result.ChainKey, "different chain key")
		}
		chainKey = result.ChainKey
		privateKey.Add(group.NewScalar().Set(lagrangeCoefficients[result.ID]).Mul(result.PrivateShare))
	}

	actualPublicKey := privateKey.ActOnBase()

	require.True(t, publicKey.Equal(actualPublicKey))

	shares := make(map[party.ID]curve.Scalar)
	for _, result := range results {
		shares[result.ID] = result.PrivateShare
	}

	for _, result := range results {
		for _, id := range parties {
			expected := shares[id].ActOnBase()
			require.True(t, result.VerificationShares.Points[id].Equal(expected), "different verification shares", id)
		}
		marshalled, err := cbor.Marshal(result)
		require.NoError(t, err)
		unmarshalledResult := EmptyConfig(group)
		err = cbor.Unmarshal(marshalled, unmarshalledResult)
		require.NoError(t, err)
		for _, id := range parties {
			expected := shares[id].ActOnBase()
			require.True(t, unmarshalledResult.VerificationShares.Points[id].Equal(expected))
		}
	}
}

func TestKeygen(t *testing.T) {
	group := curve.Secp256k1{}
	N := 5
	partyIDs := test.PartyIDs(N)

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		r, err := StartKeygenCommon(false, group, partyIDs, N-1, partyID, nil, nil, nil)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	checkOutput(t, rounds, partyIDs)
}

func checkOutputTaproot(t *testing.T, rounds []round.Session, parties party.IDSlice) {
	group := curve.Secp256k1{}

	N := len(rounds)
	results := make([]TaprootConfig, 0, N)
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, &TaprootConfig{}, resultRound.Result, "expected taproot result")
		result := resultRound.Result.(*TaprootConfig)
		results = append(results, *result)
		require.Equal(t, r.SelfID(), result.ID, "party IDs should be the same")
	}

	var publicKey []byte
	var chainKey []byte
	privateKey := group.NewScalar()
	lagrangeCoefficients := polynomial.Lagrange(group, parties)
	for _, result := range results {
		if publicKey != nil {
			assert.EqualValues(t, publicKey, result.PublicKey, "different public keys")
		}
		publicKey = result.PublicKey
		if chainKey != nil {
			assert.Equal(t, chainKey, result.ChainKey, "different chain keys")
		}
		chainKey = result.ChainKey
		privateKey.Add(group.NewScalar().Set(lagrangeCoefficients[result.ID]).Mul(result.PrivateShare))
	}
	effectivePublic, err := curve.Secp256k1{}.LiftX(publicKey)
	require.NoError(t, err)

	actualPublicKey := privateKey.ActOnBase()

	require.True(t, actualPublicKey.Equal(effectivePublic))

	shares := make(map[party.ID]curve.Scalar)
	for _, result := range results {
		shares[result.ID] = result.PrivateShare
	}

	for _, result := range results {
		for _, id := range parties {
			expected := shares[id].ActOnBase()
			assert.True(t, result.VerificationShares[id].Equal(expected))
		}
	}
}

func TestKeygenTaproot(t *testing.T) {
	N := 5
	partyIDs := test.PartyIDs(N)
	group := curve.Secp256k1{}

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		r, err := StartKeygenCommon(true, group, partyIDs, N-1, partyID, nil, nil, nil)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)

	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	checkOutputTaproot(t, rounds, partyIDs)
}
