package sign

import (
	"crypto/rand"
	"crypto/sha256"
	"reflect"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/frost/keygen"
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
		msgBytes, err := proto.Marshal(msg)
		require.NoError(t, err, "failed to marshal message")
		for idJ, r := range rounds {
			var m message.Message
			require.NoError(t, proto.Unmarshal(msgBytes, &m), "failed to unmarshal message")
			if m.From == idJ {
				continue
			}
			if len(msg.To) == 0 || party.IDSlice(msg.To).Contains(idJ) {
				content := r.MessageContent()
				err = msg.UnmarshalContent(content)
				require.NoError(t, err)
				require.NoError(t, r.ProcessMessage(msg.From, content))
			}
		}
	}

	t.Logf("round %v done", expectedRoundType)
}

func checkOutput(t *testing.T, rounds map[party.ID]round.Round, public *curve.Point, m []byte) {
	for _, r := range rounds {
		resultRound, ok := r.(*round.Output)
		assert.True(t, ok)
		signature, ok := resultRound.Result.(Signature)
		assert.True(t, ok)
		assert.True(t, signature.Verify(public, m))
	}
}

func TestSign(t *testing.T) {
	N := 5
	threshold := 2

	partyIDs := party.RandomIDs(N)

	secret := sample.Scalar(rand.Reader)
	f := polynomial.NewPolynomial(threshold, secret)
	publicKey := curve.NewIdentityPoint().ScalarBaseMult(secret)
	steak := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)

	privateShares := make(map[party.ID]*curve.Scalar, N)
	for _, id := range partyIDs {
		privateShares[id] = f.Evaluate(id.Scalar())
	}

	verificationShares := make(map[party.ID]*curve.Point, N)
	for _, id := range partyIDs {
		verificationShares[id] = curve.NewIdentityPoint().ScalarBaseMult(privateShares[id])
	}

	var newPublicKey *curve.Point
	rounds := make(map[party.ID]round.Round, N)
	for _, id := range partyIDs {
		result := &keygen.Result{
			ID:                 id,
			Threshold:          threshold,
			PublicKey:          publicKey,
			PrivateShare:       privateShares[id],
			VerificationShares: verificationShares,
			ChainKey:           chainKey,
		}
		result, _ = result.DeriveChild(1)
		if newPublicKey == nil {
			newPublicKey = result.PublicKey
		}
		r, _, err := StartSign(result, partyIDs, steak)()
		require.NoError(t, err, "round creation should not result in an error")
		rounds[id] = r
	}

	for _, roundType := range roundTypes {
		processRound(t, rounds, roundType)
	}

	checkOutput(t, rounds, newPublicKey, steak)
}

func checkOutputTaproot(t *testing.T, rounds map[party.ID]round.Round, public taproot.PublicKey, m []byte) {
	for _, r := range rounds {
		resultRound, ok := r.(*round.Output)
		assert.True(t, ok)
		signature, ok := resultRound.Result.(taproot.Signature)
		assert.True(t, ok)
		assert.True(t, public.Verify(signature, m))
	}
}

func TestSignTaproot(t *testing.T) {
	N := 5
	threshold := 2

	partyIDs := party.RandomIDs(N)

	secret := sample.Scalar(rand.Reader)
	publicPoint := curve.NewIdentityPoint().ScalarBaseMult(secret)
	if !publicPoint.HasEvenY() {
		secret.Negate(secret)
	}
	f := polynomial.NewPolynomial(threshold, secret)
	publicKey := taproot.PublicKey(publicPoint.XBytes()[:])
	steakHash := sha256.New()
	_, _ = steakHash.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	steak := steakHash.Sum(nil)
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)

	privateShares := make(map[party.ID]*curve.Scalar, N)
	for _, id := range partyIDs {
		privateShares[id] = f.Evaluate(id.Scalar())
	}

	verificationShares := make(map[party.ID]*curve.Point, N)
	for _, id := range partyIDs {
		verificationShares[id] = curve.NewIdentityPoint().ScalarBaseMult(privateShares[id])
	}

	var newPublicKey []byte
	rounds := make(map[party.ID]round.Round, N)
	for _, id := range partyIDs {
		result := &keygen.TaprootResult{
			ID:                 id,
			Threshold:          threshold,
			PublicKey:          publicKey,
			PrivateShare:       privateShares[id],
			VerificationShares: verificationShares,
		}
		result, _ = result.DeriveChild(1)
		if newPublicKey == nil {
			newPublicKey = result.PublicKey
		}
		r, _, err := StartSignTaproot(result, partyIDs, steak)()
		require.NoError(t, err, "round creation should not result in an error")
		rounds[id] = r
	}

	for _, roundType := range roundTypes {
		processRound(t, rounds, roundType)
	}

	checkOutputTaproot(t, rounds, newPublicKey, steak)
}
