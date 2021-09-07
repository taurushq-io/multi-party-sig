package presign

import (
	mrand "math/rand"
	"testing"

	"github.com/cronokirby/safenum"
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
	oneNat      = new(safenum.Nat).SetUint64(1)
	oneInt      = new(safenum.Int).SetNat(oneNat)
	minusOneInt = new(safenum.Int).SetNat(oneNat).Neg(1)

	N           = 4
	T           = N - 1
	group       = curve.Secp256k1{}
	configs     map[party.ID]*config.Config
	partyIDs    party.IDSlice
	messageHash []byte
)

func init() {
	source := mrand.New(mrand.NewSource(1))
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs, partyIDs = test.GenerateConfig(group, N, T, source, pl)
	for id, c := range configs {
		configs[id], _ = c.DeriveBIP32(0)
	}

	messageHash = make([]byte, 64)
	sha3.ShakeSum128(messageHash, []byte("hello"))
}

func TestRound(t *testing.T) {

	rounds := make([]round.Session, 0, N)
	for _, c := range configs {
		pl := pool.NewPool(1)
		defer pl.TearDown()
		r, err := StartPresign(c, partyIDs, messageHash, pl)(nil)
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
	for _, r := range rounds {
		assert.IsType(t, &round.Output{}, r)
		signature, ok := r.(*round.Output).Result.(*ecdsa.Signature)
		assert.True(t, ok, "result should *ecdsa.Signature")
		assert.True(t, signature.Verify(configs[r.SelfID()].PublicPoint(), messageHash))
	}
}
