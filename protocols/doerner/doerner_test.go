package doerner

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/doerner/keygen"
)

func runHandler(wg *sync.WaitGroup, id party.ID, handler protocol.Handler, network *test.Network) {
	defer wg.Done()
	test.HandlerLoop(id, handler, network)
}

var testGroup = curve.Secp256k1{}

func runKeygen(partyIDs party.IDSlice) (*ConfigSender, *ConfigReceiver, error) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	h0, err := protocol.NewTwoPartyHandler(Keygen(testGroup, true, partyIDs[0], partyIDs[1], pl), []byte("session"), true)
	if err != nil {
		return nil, nil, err
	}
	h1, err := protocol.NewTwoPartyHandler(Keygen(testGroup, false, partyIDs[1], partyIDs[0], pl), []byte("session"), false)
	if err != nil {
		return nil, nil, err
	}
	var wg sync.WaitGroup
	network := test.NewNetwork(partyIDs)
	wg.Add(2)
	go runHandler(&wg, partyIDs[0], h0, network)
	go runHandler(&wg, partyIDs[1], h1, network)
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

func runRefresh(partyIDs party.IDSlice, configSender *ConfigSender, configReceiver *ConfigReceiver) (*ConfigSender, *ConfigReceiver, error) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	h0, err := protocol.NewTwoPartyHandler(RefreshReceiver(configReceiver, partyIDs[0], partyIDs[1], pl), []byte("session"), true)
	if err != nil {
		return nil, nil, err
	}
	h1, err := protocol.NewTwoPartyHandler(RefreshSender(configSender, partyIDs[1], partyIDs[0], pl), []byte("session"), false)
	if err != nil {
		return nil, nil, err
	}
	var wg sync.WaitGroup
	network := test.NewNetwork(partyIDs)
	wg.Add(2)
	go runHandler(&wg, partyIDs[0], h0, network)
	go runHandler(&wg, partyIDs[1], h1, network)
	wg.Wait()

	resultRound0, err := h0.Result()
	if err != nil {
		return nil, nil, err
	}
	newConfigReceiver, ok := resultRound0.(*ConfigReceiver)
	if !ok {
		return nil, nil, errors.New("failed to cast result to *ConfigReceiver")
	}

	resultRound1, err := h1.Result()
	if err != nil {
		return nil, nil, err
	}
	newConfigSender, ok := resultRound1.(*ConfigSender)
	if !ok {
		return nil, nil, errors.New("failed to cast result to *ConfigSender")
	}

	return newConfigSender, newConfigReceiver, nil
}

var testHash = []byte("test hash")

func runSign(partyIDs party.IDSlice, configSender *keygen.ConfigSender, configReceiver *keygen.ConfigReceiver) (*ecdsa.Signature, error) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	h0, err := protocol.NewTwoPartyHandler(SignReceiver(configReceiver, partyIDs[0], partyIDs[1], testHash, pl), []byte("session"), true)
	if err != nil {
		return nil, err
	}
	h1, err := protocol.NewTwoPartyHandler(SignSender(configSender, partyIDs[1], partyIDs[0], testHash, pl), []byte("session"), true)
	if err != nil {
		return nil, err
	}
	var wg sync.WaitGroup
	network := test.NewNetwork(partyIDs)
	wg.Add(2)
	go runHandler(&wg, partyIDs[0], h0, network)
	go runHandler(&wg, partyIDs[1], h1, network)
	wg.Wait()

	resultRound0, err := h0.Result()
	if err != nil {
		return nil, err
	}
	sig, ok := resultRound0.(*ecdsa.Signature)
	if !ok {
		return nil, errors.New("failed to cast result to Signature")
	}
	return sig, nil
}

func checkKeygenOutput(t *testing.T, configSender *ConfigSender, configReceiver *ConfigReceiver) {
	require.True(t, configSender.Public.Equal(configReceiver.Public))
	require.False(t, configSender.Public.IsIdentity())
	secret := configSender.Group().NewScalar().Set(configSender.SecretShare).Add(configReceiver.SecretShare)
	public := secret.ActOnBase()
	require.True(t, public.Equal(configSender.Public))
	require.True(t, bytes.Equal(configSender.ChainKey, configReceiver.ChainKey))
}

func TestSign(t *testing.T) {
	partyIDs := test.PartyIDs(2)

	configSender, configReceiver, err := runKeygen(partyIDs)
	require.NoError(t, err)
	checkKeygenOutput(t, configSender, configReceiver)

	sig, err := runSign(partyIDs, configSender, configReceiver)
	require.NoError(t, err)
	require.True(t, sig.Verify(configSender.Public, testHash))
	require.True(t, sig.Verify(configReceiver.Public, testHash))

	newConfigSender, newConfigReceiver, err := runRefresh(partyIDs, configSender, configReceiver)
	require.NoError(t, err)
	checkKeygenOutput(t, configSender, configReceiver)
	require.True(t, newConfigSender.Public.Equal(configSender.Public))
	require.True(t, newConfigReceiver.Public.Equal(configReceiver.Public))

	sig, err = runSign(partyIDs, configSender, configReceiver)
	require.NoError(t, err)
	require.True(t, sig.Verify(configSender.Public, testHash))
	require.True(t, sig.Verify(configReceiver.Public, testHash))
}

func BenchmarkSign(t *testing.B) {
	t.StopTimer()
	partyIDs := test.PartyIDs(2)
	configSender, configReceiver, _ := runKeygen(partyIDs)
	t.StartTimer()
	for i := 0; i < t.N; i++ {
		runSign(partyIDs, configSender, configReceiver)
	}
}
