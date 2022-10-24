package sign

import (
	mrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
	"golang.org/x/crypto/sha3"
)

var (
	group       = curve.Secp256k1{}
	messageHash []byte
)

func init() {
	messageToSign := []byte("hello")
	messageHash = make([]byte, 64)
	sha3.ShakeSum128(messageHash, messageToSign)
}

// generatePartiesAndKeys generates parties and their keys with T-N scheme,
// and P parties will participate in signning
func generatePartiesAndKeys(t *testing.T, T, N, P int, pl *pool.Pool) (map[party.ID]*config.Config, party.IDSlice, curve.Point) {
	t.Logf("generating configs, T=%d, N=%d", T, N)
	defer t.Logf("done generating configs, T=%d, N=%d", T, N)
	configs, partyIDs := test.GenerateConfig(group, N, T, mrand.New(mrand.NewSource(1)), pl)
	publicKey := configs[partyIDs[0]].PublicPoint()
	return configs, partyIDs[:P], publicKey
}

func signWithParties(t *testing.T, configs map[party.ID]*config.Config, partyIDs party.IDSlice, pl *pool.Pool) []round.Session {
	rounds := make([]round.Session, 0, len(partyIDs))
	for _, partyID := range partyIDs {
		c := configs[partyID]
		r, err := StartSign(c, partyIDs, messageHash, pl)(nil)
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
	return rounds
}

func verifyOutput(t *testing.T, publicKey curve.Point, output []round.Session) {
	for _, r := range output {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, &ecdsa.Signature{}, resultRound.Result, "expected taproot signature result")
		signature := resultRound.Result.(*ecdsa.Signature)
		assert.True(t, signature.Verify(publicKey, messageHash), "expected valid signature")
	}
}

func TestSignT2N5P4(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	configs, partyIDs, publicKey := generatePartiesAndKeys(t, 2, 5, 4, pl)
	output := signWithParties(t, configs, partyIDs, pl)
	verifyOutput(t, publicKey, output)
}

func TestSignT5N6P6(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	configs, partyIDs, publicKey := generatePartiesAndKeys(t, 5, 6, 6, pl)
	output := signWithParties(t, configs, partyIDs, pl)
	verifyOutput(t, publicKey, output)
}

func TestSignT4N8P6(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	configs, partyIDs, publicKey := generatePartiesAndKeys(t, 4, 8, 6, pl)
	output := signWithParties(t, configs, partyIDs, pl)
	verifyOutput(t, publicKey, output)
}
