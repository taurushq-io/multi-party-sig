package sign

import (
	mrand "math/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"golang.org/x/crypto/sha3"
)

func TestRound(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	group := curve.Secp256k1{}

	N := 6
	T := N - 1

	t.Log("generating configs")
	configs := test.GenerateConfig(group, N, T, mrand.New(mrand.NewSource(1)), pl)
	t.Log("done generating configs")

	partyIDs := make([]party.ID, 0, T+1)
	for id := range configs {
		partyIDs = append(partyIDs, id)
		if len(partyIDs) == T+1 {
			break
		}
	}
	publicPoint := configs[partyIDs[0]].PublicPoint()

	messageToSign := []byte("hello")
	messageHash := make([]byte, 64)
	sha3.ShakeSum128(messageHash, messageToSign)

	rounds := make(map[party.ID]round.Round, N)
	for _, partyID := range partyIDs {
		c := configs[partyID]
		r, _, err := StartSign(pl, c, partyIDs, messageHash)()
		require.NoError(t, err, "round creation should not result in an error")
		rounds[partyID] = r
	}

	for {
		err, done := test.Rounds(group, rounds, "", nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, &ecdsa.Signature{}, resultRound.Result, "expected taproot signature result")
		signature := resultRound.Result.(*ecdsa.Signature)
		assert.True(t, signature.Verify(publicPoint, messageHash), "expected valid signature")
	}
}

func TestProtocol(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	group := curve.Secp256k1{}

	n := 5
	threshold := 2
	ps := map[party.ID]*protocol.Handler{}

	handleMessage := func(msg *protocol.Message) {
		if msg == nil {
			return
		}
		for id, p := range ps {
			if msg.IsFor(id) {
				err := p.Update(msg)
				assert.NoError(t, err)
			}
		}
	}

	wg := new(sync.WaitGroup)
	getMessages := func(p *protocol.Handler) {
		for msg := range p.Listen() {
			handleMessage(msg)
		}
		wg.Done()
	}

	configs := test.GenerateConfig(group, n, threshold, mrand.New(mrand.NewSource(1)), pl)
	m := []byte("hello")
	var publicPoint curve.Point

	for id, c := range configs {
		if publicPoint == nil {
			publicPoint = c.PublicPoint()
		}
		p, err := protocol.NewHandler(StartSign(pl, configs[id], c.PartyIDs(), m))
		require.NoError(t, err)
		ps[id] = p
	}
	for _, p := range ps {
		wg.Add(1)
		go getMessages(p)
	}
	wg.Wait()
	for _, p := range ps {
		r, err := p.Result()
		assert.NoError(t, err)
		assert.IsType(t, &ecdsa.Signature{}, r)
		res := r.(*ecdsa.Signature)
		assert.True(t, res.Verify(publicPoint, m))
	}
}
