package sign

import (
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

func worker(wg *sync.WaitGroup, id party.ID, handler protocol.Handler, network *test.Network) {
	defer wg.Done()
	test.HandlerLoop(id, handler, network)
}

func runDoerner(partyIDs party.IDSlice) (*keygen.ConfigSender, *keygen.ConfigReceiver, error) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	group := curve.Secp256k1{}

	h0, err := protocol.NewTwoPartyHandler(keygen.StartKeygen(group, true, partyIDs[0], partyIDs[1], pl), []byte("session"), true)
	if err != nil {
		return nil, nil, err
	}
	h1, err := protocol.NewTwoPartyHandler(keygen.StartKeygen(group, false, partyIDs[1], partyIDs[0], pl), []byte("session"), false)
	if err != nil {
		return nil, nil, err
	}
	var wg sync.WaitGroup
	network := test.NewNetwork(partyIDs)
	wg.Add(2)
	go worker(&wg, partyIDs[0], h0, network)
	go worker(&wg, partyIDs[1], h1, network)
	wg.Wait()

	resultRound0, err := h0.Result()
	if err != nil {
		return nil, nil, err
	}
	configReceiver, ok := resultRound0.(*keygen.ConfigReceiver)
	if !ok {
		return nil, nil, errors.New("failed to cast result to *ConfigReceiver")
	}

	resultRound1, err := h1.Result()
	if err != nil {
		return nil, nil, err
	}
	configSender, ok := resultRound1.(*keygen.ConfigSender)
	if !ok {
		return nil, nil, errors.New("failed to cast result to *ConfigSender")
	}

	return configSender, configReceiver, nil
}

var testHash = []byte("test hash")

func runDoernerSign(partyIDs party.IDSlice, configSender *keygen.ConfigSender, configReceiver *keygen.ConfigReceiver) (*ecdsa.Signature, error) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	h0, err := protocol.NewTwoPartyHandler(StartSignReceiver(configReceiver, partyIDs[0], partyIDs[1], testHash, pl), []byte("session"), true)
	if err != nil {
		return nil, err
	}
	h1, err := protocol.NewTwoPartyHandler(StartSignSender(configSender, partyIDs[1], partyIDs[0], testHash, pl), []byte("session"), true)
	if err != nil {
		return nil, err
	}
	var wg sync.WaitGroup
	network := test.NewNetwork(partyIDs)
	wg.Add(2)
	go worker(&wg, partyIDs[0], h0, network)
	go worker(&wg, partyIDs[1], h1, network)
	wg.Wait()

	resultRound0, err := h0.Result()
	if err != nil {
		return nil, err
	}
	sig, ok := resultRound0.(ecdsa.Signature)
	if !ok {
		return nil, errors.New("failed to cast result to Signature")
	}
	return &sig, nil
}

func TestSign(t *testing.T) {
	partyIDs := test.PartyIDs(2)
	configSender, configReceiver, err := runDoerner(partyIDs)
	require.NoError(t, err)
	sig, err := runDoernerSign(partyIDs, configSender, configReceiver)
	require.NoError(t, err)
	require.True(t, sig.Verify(configSender.Public, testHash))
	require.True(t, sig.Verify(configReceiver.Public, testHash))
}

func BenchmarkSign(t *testing.B) {
	t.StopTimer()
	partyIDs := test.PartyIDs(2)
	configSender, configReceiver, _ := runDoerner(partyIDs)
	t.StartTimer()
	for i := 0; i < t.N; i++ {
		runDoernerSign(partyIDs, configSender, configReceiver)
	}
}
