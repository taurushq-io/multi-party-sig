package sign

import (
	"crypto/rand"
	"crypto/sha256"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/frost/keygen"
)

var roundTypes = []reflect.Type{
	reflect.TypeOf(&round1{}),
	reflect.TypeOf(&round2{}),
	reflect.TypeOf(&round3{}),
}

func checkOutput(t *testing.T, rounds map[party.ID]round.Round, public curve.Point, m []byte) {
	for _, r := range rounds {
		resultRound, ok := r.(*round.Output)
		assert.True(t, ok)
		signature, ok := resultRound.Result.(Signature)
		assert.True(t, ok)
		assert.True(t, signature.Verify(public, m))
	}
}

func TestSign(t *testing.T) {
	group := curve.Secp256k1{}

	N := 5
	threshold := 2

	partyIDs := party.RandomIDs(N)

	secret := sample.Scalar(rand.Reader, group)
	f := polynomial.NewPolynomial(group, threshold, secret)
	publicKey := secret.ActOnBase()
	steak := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)

	privateShares := make(map[party.ID]curve.Scalar, N)
	for _, id := range partyIDs {
		privateShares[id] = f.Evaluate(id.Scalar(group))
	}

	verificationShares := make(map[party.ID]curve.Point, N)
	for _, id := range partyIDs {
		verificationShares[id] = privateShares[id].ActOnBase()
	}

	var newPublicKey curve.Point
	rounds := make(map[party.ID]round.Round, N)
	for _, id := range partyIDs {
		result := &keygen.Result{
			ID:                 id,
			Group:              group,
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
		t.Logf("starting round %v", roundType)
		if err := round.ProcessRounds(group, rounds); err != nil {
			require.NoError(t, err, "failed to process round")
		}
		t.Logf("round %v done", roundType)
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
	group := curve.Secp256k1{}
	N := 5
	threshold := 2

	partyIDs := party.RandomIDs(N)

	secret := sample.Scalar(rand.Reader, group)
	publicPoint := secret.ActOnBase()
	if !publicPoint.(*curve.Secp256k1Point).HasEvenY() {
		secret.Negate()
	}
	f := polynomial.NewPolynomial(group, threshold, secret)
	publicKey := taproot.PublicKey(publicPoint.(*curve.Secp256k1Point).XBytes())
	steakHash := sha256.New()
	_, _ = steakHash.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	steak := steakHash.Sum(nil)
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)

	privateShares := make(map[party.ID]curve.Scalar, N)
	for _, id := range partyIDs {
		privateShares[id] = f.Evaluate(id.Scalar(group))
	}

	verificationShares := make(map[party.ID]curve.Point, N)
	for _, id := range partyIDs {
		verificationShares[id] = privateShares[id].ActOnBase()
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
		t.Logf("starting round %v", roundType)
		if err := round.ProcessRounds(group, rounds); err != nil {
			require.NoError(t, err, "failed to process round")
		}
		t.Logf("round %v done", roundType)
	}

	checkOutputTaproot(t, rounds, newPublicKey, steak)
}
