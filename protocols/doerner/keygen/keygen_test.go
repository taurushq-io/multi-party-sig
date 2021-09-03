package keygen

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

func checkOutput(t *testing.T, configSender *ConfigSender, configReceiver *ConfigReceiver) {
	require.True(t, configSender.Public.Equal(configReceiver.Public))
	require.False(t, configSender.Public.IsIdentity())
	secret := configSender.Group().NewScalar().Set(configSender.SecretShare).Mul(configReceiver.SecretShare)
	public := secret.ActOnBase()
	require.True(t, public.Equal(configSender.Public))
}

func worker(wg *sync.WaitGroup, id party.ID, handler protocol.Handler, network *test.Network) {
	defer wg.Done()
	test.HandlerLoop(id, handler, network)
}

func TestKeygen(t *testing.T) {
	var pl *pool.Pool

	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(2)
	network := test.NewNetwork(partyIDs)

	var wg sync.WaitGroup
	h0, err := protocol.NewTwoPartyHandler(StartKeygen(group, true, partyIDs[0], partyIDs[1], pl), []byte("session"), true)
	require.NoError(t, err, "round creation should not result in an error")
	h1, err := protocol.NewTwoPartyHandler(StartKeygen(group, false, partyIDs[1], partyIDs[0], pl), []byte("session"), false)
	require.NoError(t, err, "round creation should not result in an error")
	wg.Add(2)
	go worker(&wg, partyIDs[0], h0, network)
	go worker(&wg, partyIDs[1], h1, network)
	wg.Wait()

	resultRound0, err := h0.Result()
	require.NoError(t, err)
	configReceiver, ok := resultRound0.(*ConfigReceiver)
	require.True(t, ok)

	resultRound1, err := h1.Result()
	require.NoError(t, err)
	configSender, ok := resultRound1.(*ConfigSender)
	require.True(t, ok)

	checkOutput(t, configSender, configReceiver)
}
