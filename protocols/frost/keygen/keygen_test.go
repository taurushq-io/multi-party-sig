package keygen

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
)

var roundTypes = []reflect.Type{
	reflect.TypeOf(&round1{}),
	reflect.TypeOf(&round2{}),
	reflect.TypeOf(&round3{}),
}

func processRound(t *testing.T, rounds map[party.ID]round.Round, expectedRoundType reflect.Type) {
	N := len(rounds)
	t.Logf("starting round %v", expectedRoundType)
	// get the second set of  messages
	out := make(chan *message.Message, N*N)
	for idJ, r := range rounds {
		require.EqualValues(t, expectedRoundType, reflect.TypeOf(r))
		newRound, err := r.Finalize(out)
		require.NoError(t, err, "failed to generate messages")
		if newRound != nil {
			rounds[idJ] = newRound
		}
	}
	close(out)

	for msg := range out {
		msgBytes, err := cbor.Marshal(msg)
		require.NoError(t, err, "failed to marshal message")
		for idJ, r := range rounds {
			var m message.Message
			require.NoError(t, cbor.Unmarshal(msgBytes, &m), "failed to unmarshal message")
			if m.From == idJ {
				continue
			}
			if msg.IsFor(idJ) {
				content := r.MessageContent()
				err = msg.UnmarshalContent(content)
				require.NoError(t, err)
				require.NoError(t, r.VerifyMessage(msg.From, idJ, content))
				require.NoError(t, r.StoreMessage(msg.From, content))
			}
		}
	}

	t.Logf("round %v done", expectedRoundType)
}

func checkOutput(t *testing.T, rounds map[party.ID]round.Round, parties party.IDSlice) {
	group := curve.Secp256k1{}

	N := len(rounds)
	results := make([]Result, 0, N)
	for id, r := range rounds {
		resultRound, ok := r.(*round.Output)
		require.True(t, ok)
		result, ok := resultRound.Result.(*Result)
		require.True(t, ok)
		results = append(results, *result)
		require.Equal(t, id, result.ID)
	}

	var publicKey curve.Point
	var chainKey []byte
	privateKey := group.NewScalar()
	lagrangeCoefficients := polynomial.Lagrange(group, parties)
	for _, result := range results {
		if publicKey != nil {
			assert.True(t, publicKey.Equal(result.PublicKey))
		}
		publicKey = result.PublicKey
		if chainKey != nil {
			assert.True(t, bytes.Equal(chainKey, result.ChainKey))
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
		for _, party := range parties {
			expected := shares[party].ActOnBase()
			require.True(t, result.VerificationShares[party].Equal(expected))
		}
	}
}

func TestKeygen(t *testing.T) {
	N := 5
	partyIDs := party.RandomIDs(N)

	rounds := make(map[party.ID]round.Round, N)
	for _, partyID := range partyIDs {
		r, _, err := StartKeygen(partyIDs, N-1, partyID)()
		require.NoError(t, err, "round creation should not result in an error")
		rounds[partyID] = r

	}

	for _, roundType := range roundTypes {
		processRound(t, rounds, roundType)
	}

	checkOutput(t, rounds, partyIDs)
}

func checkOutputTaproot(t *testing.T, rounds map[party.ID]round.Round, parties party.IDSlice) {
	group := curve.Secp256k1{}

	N := len(rounds)
	results := make([]TaprootResult, 0, N)
	for id, r := range rounds {
		resultRound, ok := r.(*round.Output)
		require.True(t, ok)
		result, ok := resultRound.Result.(*TaprootResult)
		require.True(t, ok)
		results = append(results, *result)
		require.Equal(t, id, result.ID)
	}

	var publicKey []byte
	var chainKey []byte
	privateKey := group.NewScalar()
	lagrangeCoefficients := polynomial.Lagrange(group, parties)
	for _, result := range results {
		if publicKey != nil {
			assert.True(t, bytes.Equal(publicKey, result.PublicKey))
		}
		publicKey = result.PublicKey
		if chainKey != nil {
			assert.True(t, bytes.Equal(chainKey, result.ChainKey))
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
		for _, party := range parties {
			expected := shares[party].ActOnBase()
			assert.True(t, result.VerificationShares[party].Equal(expected))
		}
	}
}

func TestKeygenTaproot(t *testing.T) {
	N := 5
	partyIDs := party.RandomIDs(N)

	rounds := make(map[party.ID]round.Round, N)
	for _, partyID := range partyIDs {
		r, _, err := StartKeygenTaproot(partyIDs, N-1, partyID)()
		require.NoError(t, err, "round creation should not result in an error")
		rounds[partyID] = r

	}

	for _, roundType := range roundTypes {
		processRound(t, rounds, roundType)
	}

	checkOutputTaproot(t, rounds, partyIDs)
}
