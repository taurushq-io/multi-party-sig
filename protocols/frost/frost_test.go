package frost

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
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

func do(t *testing.T, id party.ID, ids []party.ID, threshold int, message []byte, adaptorSecret curve.Secp256k1Scalar, n *test.Network, wg *sync.WaitGroup) {
	defer wg.Done()
	h, err := protocol.NewMultiHandler(Keygen(curve.Secp256k1{}, id, ids, threshold), nil)
	require.NoError(t, err)
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c0 := r.(*Config)

	h, err = protocol.NewMultiHandler(Refresh(c0, ids), nil)
	require.NoError(t, err)
	test.HandlerLoop(id, h, n)
	r, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c := r.(*Config)
	require.True(t, c0.PublicKey.Equal(c.PublicKey))

	h, err = protocol.NewMultiHandler(KeygenTaproot(id, ids, threshold), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	r, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &TaprootConfig{}, r)

	c0Taproot := r.(*TaprootConfig)

	h, err = protocol.NewMultiHandler(RefreshTaproot(c0Taproot, ids), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	r, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &TaprootConfig{}, r)

	cTaproot := r.(*TaprootConfig)
	require.True(t, bytes.Equal(c0Taproot.PublicKey, cTaproot.PublicKey))

	h, err = protocol.NewMultiHandler(Sign(c, ids, message), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, Signature{}, signResult)
	signature := signResult.(Signature)
	assert.True(t, signature.Verify(c.PublicKey, message))

	h, err = protocol.NewMultiHandler(SignTaproot(cTaproot, ids, message), nil)
	require.NoError(t, err)

	test.HandlerLoop(c.ID, h, n)

	signResult, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, taproot.Signature{}, signResult)
	taprootSignature := signResult.(taproot.Signature)
	assert.True(t, cTaproot.PublicKey.Verify(taprootSignature, message))

	adaptorPoint := adaptorSecret.ActOnBase().(*curve.Secp256k1Point)
	h, err = protocol.NewMultiHandler(SignTaprootAdaptor(cTaproot, ids, *adaptorPoint, message), nil)
	require.NoError(t, err)

	test.HandlerLoop(c.ID, h, n)
	signResult, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, taproot.AdaptorSignature{}, signResult)
	adaptorSignature := signResult.(taproot.AdaptorSignature)
	assert.True(t, cTaproot.PublicKey.VerifyAdaptor(adaptorSignature, *adaptorPoint, message))
	finalSignature, err := adaptorSignature.Complete(adaptorSecret)
	require.NoError(t, err)
	assert.True(t, cTaproot.PublicKey.Verify(finalSignature, message))
}

func doDkgOnly(t *testing.T, id party.ID, ids []party.ID, threshold int, n *test.Network) Config {
	h, err := protocol.NewMultiHandler(Keygen(curve.Secp256k1{}, id, ids, threshold), nil)
	require.NoError(t, err)
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	return *r.(*Config)
}

func doRefreshOnly(t *testing.T, c Config, ids []party.ID, n *test.Network) Config {
	h, err := protocol.NewMultiHandler(Refresh(&c, ids), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	return *r.(*Config)
}

func doRepairOnly(t *testing.T, helpers []party.ID, lostID, selfID party.ID, privateShare curve.Scalar, n *test.Network) curve.Scalar {
	h, err := protocol.NewMultiHandler(Repair(helpers, lostID, selfID, privateShare), nil)
	require.NoErrorf(t, err, "error in Repair for %s", selfID)
	test.HandlerLoop(selfID, h, n)
	res, err := h.Result()
	require.NoError(t, err)
	return res.(curve.Scalar)
}

func doSigningOnly(t *testing.T, c Config, ids []party.ID, message []byte, n *test.Network, wg *sync.WaitGroup) {
	defer wg.Done()
	h, err := protocol.NewMultiHandler(Sign(&c, ids, message), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, Signature{}, signResult)
	signature := signResult.(Signature)
	assert.True(t, signature.Verify(c.PublicKey, message))
}

// This test is preserved for parity with upstream, but it isn't realistic.
// Particularly, by setting T = N-1, we are effectively testing a 1-of-N scheme.
// Also, _every_ share is part of the signing group.
// The tests below this one check more realistic scenarios.
func TestFrost(t *testing.T) {
	N := 5
	T := N - 1
	message := []byte("hello")

	group := curve.Secp256k1{}
	adaptorSecret := sample.Scalar(rand.Reader, group).(*curve.Secp256k1Scalar)

	partyIDs := test.PartyIDs(N)
	fmt.Println(partyIDs)

	n := test.NewNetwork(partyIDs)

	var wg sync.WaitGroup
	wg.Add(N)
	for _, id := range partyIDs {
		go do(t, id, partyIDs, T, message, *adaptorSecret, n, &wg)
	}
	wg.Wait()
}

func TestFrostRealisticSign(t *testing.T) {
	// this is (however unintuitively) a 3 of 5 scheme
	// (max two parties corrupted during keygen)
	N := 5
	T := 2
	message := []byte("hello")

	partyIDs := test.PartyIDs(N)

	dkgNetwork := test.NewNetwork(partyIDs)

	configs := make(map[party.ID]Config, N)
	// we will use this to show that refresh generates all-new private shares
	privateShareSet := make(map[[32]byte]struct{}, N)
	var wg sync.WaitGroup
	wg.Add(N)
	var mtx sync.Mutex
	for _, id := range partyIDs {
		go func() {
			defer wg.Done()
			c := doDkgOnly(t, id, partyIDs, T, dkgNetwork)

			b, err := c.PrivateShare.MarshalBinary()
			require.NoError(t, err)
			var arr [32]byte
			copy(arr[:], b)

			mtx.Lock()
			defer mtx.Unlock()
			configs[c.ID] = c
			privateShareSet[arr] = struct{}{}
		}()
	}
	wg.Wait()

	signingIDs := test.PartyIDs(3) // meets quorum
	signNetwork := test.NewNetwork(signingIDs)
	wg.Add(len(signingIDs))
	for _, id := range signingIDs {
		c := configs[id]
		go doSigningOnly(t, c, signingIDs, message, signNetwork, &wg)
	}
	wg.Wait()

	// note that we are only refreshing 3 of the 5 available parties
	wg.Add(len(signingIDs))
	for _, id := range signingIDs {
		c := configs[id]
		go func() {
			defer wg.Done()
			// we're reusing signNetwork here, since we have identical parties
			c = doRefreshOnly(t, c, signingIDs, signNetwork)

			b, err := c.PrivateShare.MarshalBinary()
			require.NoError(t, err)
			var arr [32]byte
			copy(arr[:], b)

			mtx.Lock()
			defer mtx.Unlock()
			_, found := privateShareSet[arr]
			require.False(t, found, "private share %v was not refreshed", id)
			configs[c.ID] = c
		}()
	}
	wg.Wait()

	wg.Add(len(signingIDs))
	for _, id := range signingIDs {
		c := configs[id]
		go doSigningOnly(t, c, signingIDs, message, signNetwork, &wg)
	}
	wg.Wait()

	// The d share below is one of the lost/non-refreshed shares.
	// Signing is expected to fail:
	// d cannot sign with the refreshed shares a and b
	signingIDs = []party.ID{"a", "b", "d"}
	signNetwork = test.NewNetwork(signingIDs)
	wg.Add(len(signingIDs))
	for _, id := range signingIDs {
		c := configs[id]
		go func() {
			defer wg.Done()
			h, err := protocol.NewMultiHandler(Sign(&c, signingIDs, message), nil)
			require.NoError(t, err)
			test.HandlerLoop(c.ID, h, signNetwork)

			_, err = h.Result()
			require.Error(t, err)
			// Some other aspects of the error text can be non-deterministic,
			// depending on goroutine timing, so we only check for the presence
			// of this crucial text, indicating which part of the FROST algorithm failed.
			require.ErrorContains(t, err, "round 3: failed to verify response")
		}()
	}
	wg.Wait()
}

func TestFrostSigningFailToMeetQuorum(t *testing.T) {
	// this is (however unintuitively) a 3 of 5 scheme
	// (max two parties corrupted during keygen)
	N := 5
	T := 2
	message := []byte("hello")

	partyIDs := test.PartyIDs(N)

	dkgNetwork := test.NewNetwork(partyIDs)

	configs := make(map[party.ID]Config)
	var wg sync.WaitGroup
	wg.Add(N)
	var mtx sync.Mutex
	for _, id := range partyIDs {
		go func() {
			c := doDkgOnly(t, id, partyIDs, T, dkgNetwork)
			mtx.Lock()
			configs[c.ID] = c
			mtx.Unlock()
			wg.Done()
		}()
	}
	wg.Wait()

	signingIDs := test.PartyIDs(2) // fails to meet quorum
	var signWg sync.WaitGroup
	signWg.Add(len(signingIDs))
	for _, id := range signingIDs {
		c := configs[id]
		go func() {
			defer signWg.Done()

			_, err := protocol.NewMultiHandler(Sign(&c, signingIDs, message), nil)
			require.Error(t, err)
			// This is a counterintuitive error message: the "threshold" in question is the DKG threshold,
			// which is one less than the "m" value in an "m of n" scheme. We don't alter the error message
			// to something more intuitive in order to keep tracking upstream.
			expected := "protocol: failed to create round: sign.StartSign: session: threshold 2 is invalid for number of parties 2"
			require.Equal(t, expected, err.Error())
		}()
	}
	signWg.Wait()
}

func TestFrostRepair(t *testing.T) {
	// this is (however unintuitively) a 3 of 5 scheme
	// (max two parties corrupted during keygen)
	N := 5
	T := 2
	//message := []byte("hello")

	partyIDs := test.PartyIDs(N)

	dkgNetwork := test.NewNetwork(partyIDs)

	configs := make(map[party.ID]Config)
	var wg sync.WaitGroup
	wg.Add(N)
	var mtx sync.Mutex
	for _, id := range partyIDs {
		go func() {
			c := doDkgOnly(t, id, partyIDs, T, dkgNetwork)
			mtx.Lock()
			configs[c.ID] = c
			mtx.Unlock()
			wg.Done()
		}()
	}
	wg.Wait()

	helperIDs := []party.ID{"a", "b", "c"}
	lostID := party.ID("d")
	participants := make([]party.ID, 0, len(helperIDs)+1)
	participants = append(participants, helperIDs...)
	participants = append(participants, lostID)
	repairNetwork := test.NewNetwork(participants)
	wg.Add(len(participants))
	var repairedShare curve.Scalar
	for _, id := range participants {
		var privateShare curve.Scalar
		if id != lostID {
			c := configs[id]
			privateShare = c.PrivateShare
		}
		go func() {
			defer wg.Done()
			res := doRepairOnly(t, helperIDs, lostID, id, privateShare, repairNetwork)
			if id == lostID {
				repairedShare = res
			}
		}()
	}
	wg.Wait()

	// check that the repaired share is correct
	require.Equal(t, repairedShare, configs[lostID].PrivateShare)
	// craft a new config using the repaired share
	// for the future: is it possible to restore the verification shares without copying them?
	restoredConfig := Config{
		ID:                 lostID,
		Threshold:          T,
		PrivateShare:       repairedShare,
		PublicKey:          configs[lostID].PublicKey,
		ChainKey:           configs[lostID].ChainKey,
		VerificationShares: configs[lostID].VerificationShares,
	}
	configs[lostID] = restoredConfig

	// let's demonstrate signing
	signingIDs := []party.ID{"b", "c", lostID}
	signingNetwork := test.NewNetwork(signingIDs)
	wg.Add(len(signingIDs))
	for _, id := range signingIDs {
		c := configs[id]
		go doSigningOnly(t, c, signingIDs, []byte("hello"), signingNetwork, &wg)
	}
}

func TestFrostRepair1of3(t *testing.T) {
	// testing repair in a 1-of-3 scheme
	// this is a somewhat strange thing to test, as it means
	// that repair is essentially copying of a private key
	N := 3
	T := 0

	partyIDs := test.PartyIDs(N)
	dkgNetwork := test.NewNetwork(partyIDs)

	configs := make(map[party.ID]Config)
	var wg sync.WaitGroup
	wg.Add(N)
	var mtx sync.Mutex
	for _, id := range partyIDs {
		go func() {
			c := doDkgOnly(t, id, partyIDs, T, dkgNetwork)
			mtx.Lock()
			configs[c.ID] = c
			mtx.Unlock()
			wg.Done()
		}()
	}
	wg.Wait()

	helperIDs := []party.ID{"a"}
	lostID := party.ID("b")
	participants := make([]party.ID, 0, len(helperIDs)+1)
	participants = append(participants, helperIDs...)
	participants = append(participants, lostID)
	repairNetwork := test.NewNetwork(participants)
	wg.Add(len(participants))
	var repairedShare curve.Scalar
	for _, id := range participants {
		var privateShare curve.Scalar
		if id != lostID {
			c := configs[id]
			privateShare = c.PrivateShare
		}
		go func() {
			defer wg.Done()
			res := doRepairOnly(t, helperIDs, lostID, id, privateShare, repairNetwork)
			if id == lostID {
				repairedShare = res
			}
		}()
	}
	wg.Wait()

	// check that the repaired share is correct
	require.Equal(t, repairedShare, configs[lostID].PrivateShare)
	// craft a new config using the repaired share
	// for the future: is it possible to restore the verification shares without copying them?
	restoredConfig := Config{
		ID:                 lostID,
		Threshold:          T,
		PrivateShare:       repairedShare,
		PublicKey:          configs[lostID].PublicKey,
		ChainKey:           configs[lostID].ChainKey,
		VerificationShares: configs[lostID].VerificationShares,
	}
	configs[lostID] = restoredConfig

	// let's demonstrate signing
	signingIDs := []party.ID{"b"}
	signingNetwork := test.NewNetwork(signingIDs)
	wg.Add(len(signingIDs))
	for _, id := range signingIDs {
		c := configs[id]
		go doSigningOnly(t, c, signingIDs, []byte("hello"), signingNetwork, &wg)
	}

}
