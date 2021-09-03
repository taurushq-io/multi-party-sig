package keygen

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

func worker(wg *sync.WaitGroup, id party.ID, handler protocol.Handler, network *test.Network) {
	defer wg.Done()
	test.HandlerLoop(id, handler, network)
}

func runDoerner() (*ConfigSender, *ConfigReceiver, error) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(2)
	network := test.NewNetwork(partyIDs)

	var wg sync.WaitGroup
	h0, err := protocol.NewTwoPartyHandler(StartKeygen(group, true, partyIDs[0], partyIDs[1], pl), []byte("session"), true)
	if err != nil {
		return nil, nil, err
	}
	h1, err := protocol.NewTwoPartyHandler(StartKeygen(group, false, partyIDs[1], partyIDs[0], pl), []byte("session"), false)
	if err != nil {
		return nil, nil, err
	}
	wg.Add(2)
	go worker(&wg, partyIDs[0], h0, network)
	go worker(&wg, partyIDs[1], h1, network)
	wg.Wait()

	resultRound0, err := h0.Result()
	if err != nil {
		return nil, nil, err
	}
	configReceiver, ok := resultRound0.(*ConfigReceiver)
	if !ok {
		return nil, nil, errors.New("failed to cast result to *ConfigReceiver")
	}

	resultRound1, err := h1.Result()
	if err != nil {
		return nil, nil, err
	}
	configSender, ok := resultRound1.(*ConfigSender)
	if !ok {
		return nil, nil, errors.New("failed to cast result to *ConfigSender")
	}

	return configSender, configReceiver, nil
}

func TestKeygen(t *testing.T) {
	configSender, configReceiver, err := runDoerner()
	require.NoError(t, err)
	require.True(t, configSender.Public.Equal(configReceiver.Public))
	require.False(t, configSender.Public.IsIdentity())
	secret := configSender.Group().NewScalar().Set(configSender.SecretShare).Mul(configReceiver.SecretShare)
	public := secret.ActOnBase()
	require.True(t, public.Equal(configSender.Public))
}

func BenchmarkKeygen(t *testing.B) {
	for i := 0; i < t.N; i++ {
		runDoerner()
	}
}
