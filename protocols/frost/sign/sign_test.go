package sign

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/frost/keygen"
)

func checkOutput(t *testing.T, rounds []round.Session, public curve.Point, m []byte) {
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, Signature{}, resultRound.Result, "expected signature result")
		signature := resultRound.Result.(Signature)
		assert.True(t, signature.Verify(public, m), "expected valid signature")
	}
}

func TestSign(t *testing.T) {
	group := curve.Secp256k1{}

	N := 5
	threshold := 2

	partyIDs := test.PartyIDs(N)

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
	rounds := make([]round.Session, 0, N)
	for _, id := range partyIDs {
		result := &keygen.Config{
			ID:                 id,
			Threshold:          threshold,
			PublicKey:          publicKey,
			PrivateShare:       privateShares[id],
			VerificationShares: party.NewPointMap(verificationShares),
			ChainKey:           chainKey,
		}
		result, _ = result.DeriveChild(1)
		if newPublicKey == nil {
			newPublicKey = result.PublicKey
		}
		r, err := StartSignCommon(false, result, partyIDs, steak)(nil)
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

	checkOutput(t, rounds, newPublicKey, steak)
}

func checkOutputTaproot(t *testing.T, rounds []round.Session, public taproot.PublicKey, m []byte) {
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, taproot.Signature{}, resultRound.Result, "expected taproot signature result")
		signature := resultRound.Result.(taproot.Signature)
		assert.True(t, public.Verify(signature, m), "expected valid signature")
	}
}

func TestSignTaproot(t *testing.T) {
	group := curve.Secp256k1{}
	N := 5
	threshold := 2

	partyIDs := test.PartyIDs(N)

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

	privateShares := make(map[party.ID]*curve.Secp256k1Scalar, N)
	for _, id := range partyIDs {
		privateShares[id] = f.Evaluate(id.Scalar(group)).(*curve.Secp256k1Scalar)
	}

	verificationShares := make(map[party.ID]*curve.Secp256k1Point, N)
	for _, id := range partyIDs {
		verificationShares[id] = privateShares[id].ActOnBase().(*curve.Secp256k1Point)
	}

	var newPublicKey []byte
	rounds := make([]round.Session, 0, N)
	for _, id := range partyIDs {
		result := &keygen.TaprootConfig{
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
		tapRootPublicKey, err := curve.Secp256k1{}.LiftX(newPublicKey)
		genericVerificationShares := make(map[party.ID]curve.Point)
		for k, v := range result.VerificationShares {
			genericVerificationShares[k] = v
		}
		require.NoError(t, err)
		normalResult := &keygen.Config{
			ID:                 result.ID,
			Threshold:          result.Threshold,
			PrivateShare:       result.PrivateShare,
			PublicKey:          tapRootPublicKey,
			VerificationShares: party.NewPointMap(genericVerificationShares),
		}
		r, err := StartSignCommon(true, normalResult, partyIDs, steak)(nil)
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

	checkOutputTaproot(t, rounds, newPublicKey, steak)
}
