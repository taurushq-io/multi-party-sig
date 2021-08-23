package frost

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
)

func do(t *testing.T, id party.ID, ids []party.ID, threshold int, message []byte, pl *pool.Pool, n *test.Network, wg *sync.WaitGroup) {
	defer wg.Done()
	h, err := protocol.NewHandler(StartKeygen(curve.Secp256k1{}, ids, threshold, id))
	require.NoError(t, err)
	require.NoError(t, test.HandlerLoop(id, h, n))
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c := r.(*Config)

	h, err = protocol.NewHandler(StartKeygenTaproot(ids, threshold, id))
	require.NoError(t, err)
	require.NoError(t, test.HandlerLoop(c.ID, h, n))

	r, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &TaprootConfig{}, r)

	cTaproot := r.(*TaprootConfig)

	h, err = protocol.NewHandler(StartSign(c, ids, message))
	require.NoError(t, err)
	require.NoError(t, test.HandlerLoop(c.ID, h, n))

	signResult, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, Signature{}, signResult)
	signature := signResult.(Signature)
	assert.True(t, signature.Verify(c.PublicKey, message))

	h, err = protocol.NewHandler(StartSignTaproot(cTaproot, ids, message))
	require.NoError(t, err)

	require.NoError(t, test.HandlerLoop(c.ID, h, n))

	signResult, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, taproot.Signature{}, signResult)
	taprootSignature := signResult.(taproot.Signature)
	assert.True(t, cTaproot.PublicKey.Verify(taprootSignature, message))
}

func TestFrost(t *testing.T) {
	N := 5
	T := N - 1
	message := []byte("hello")

	pl := pool.NewPool(0)
	defer pl.TearDown()

	partyIDs := test.PartyIDs(N)

	n := test.NewNetwork(partyIDs)

	var wg sync.WaitGroup
	wg.Add(N)
	for _, id := range partyIDs {
		go do(t, id, partyIDs, T, message, pl, n, &wg)
	}
	wg.Wait()
}
