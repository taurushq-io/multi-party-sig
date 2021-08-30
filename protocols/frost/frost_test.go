package frost

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
)

func do(t *testing.T, id party.ID, ids []party.ID, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup) {
	defer wg.Done()
	h, err := protocol.NewHandler(Keygen(curve.Secp256k1{}, id, ids, threshold), nil)
	require.NoError(t, err)
	require.NoError(t, test.HandlerLoop(id, h, n))
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c := r.(*Config)

	h, err = protocol.NewHandler(KeygenTaproot(id, ids, threshold), nil)
	require.NoError(t, err)
	require.NoError(t, test.HandlerLoop(c.ID, h, n))

	r, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &TaprootConfig{}, r)

	cTaproot := r.(*TaprootConfig)

	h, err = protocol.NewHandler(Sign(c, ids, message), nil)
	require.NoError(t, err)
	require.NoError(t, test.HandlerLoop(c.ID, h, n))

	signResult, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, Signature{}, signResult)
	signature := signResult.(Signature)
	assert.True(t, signature.Verify(c.PublicKey, message))

	h, err = protocol.NewHandler(SignTaproot(cTaproot, ids, message), nil)
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

	partyIDs := test.PartyIDs(N)

	n := test.NewNetwork(partyIDs)

	var wg sync.WaitGroup
	wg.Add(N)
	for _, id := range partyIDs {
		go do(t, id, partyIDs, T, message, n, &wg)
	}
	wg.Wait()
}
