package keygen

import (
	mrand "math/rand"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
)

var roundTypes = []reflect.Type{
	reflect.TypeOf(&round1{}),
	reflect.TypeOf(&round2{}),
	reflect.TypeOf(&round3{}),
	reflect.TypeOf(&round4{}),
	reflect.TypeOf(&round5{}),
}

var group = curve.Secp256k1{}

func checkOutput(t *testing.T, rounds map[party.ID]round.Round) {
	N := len(rounds)
	newConfigs := make([]*config.Config, 0, N)
	for _, r := range rounds {
		resultRound := r.(*round.Output)
		c := resultRound.Result.(*config.Config)
		newConfigs = append(newConfigs, c)
	}

	firstConfig := newConfigs[0]
	pk := firstConfig.PublicPoint()
	for _, c := range newConfigs {
		assert.True(t, pk.Equal(c.PublicPoint()), "RID is different")
		assert.Equal(t, firstConfig.RID, c.RID, "RID is different")
		assert.NoError(t, c.Validate(), "failed to validate new config")
	}
}

func TestKeygen(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := 2
	partyIDs := test.PartyIDs(N)

	rounds := make(map[party.ID]round.Round, N)
	for _, partyID := range partyIDs {
		r, _, err := StartKeygen(pl, group, partyIDs, N-1, partyID)()
		require.NoError(t, err, "round creation should not result in an error")
		rounds[partyID] = r
	}

	for _, roundType := range roundTypes {
		t.Logf("starting round %v", roundType)
		if err, _ := test.Rounds(group, rounds, "", nil); err != nil {
			require.NoError(t, err, "failed to process round")
		}
		t.Logf("round %v done", roundType)
	}
	checkOutput(t, rounds)
}

func TestRefresh(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := 4
	T := N - 1
	configs := test.GenerateConfig(group, N, T, mrand.New(mrand.NewSource(1)), pl)

	rounds := make(map[party.ID]round.Round, N)
	for partyID, s := range configs {
		r, _, err := StartRefresh(pl, s)()
		require.NoError(t, err, "round creation should not result in an error")
		rounds[partyID] = r

	}

	for _, roundType := range roundTypes {
		t.Logf("starting round %v", roundType)
		if err, _ := test.Rounds(group, rounds, "", nil); err != nil {
			t.Fatal(err)
		}
		t.Logf("round %v done", roundType)
	}
	checkOutput(t, rounds)
}

//func handleMessage(msg *protocol.Message, handlers map[party.ID]*protocol.Handler) error {
//	if msg == nil {
//		return nil
//	}
//	for id, h := range handlers {
//		if msg.IsFor(id) {
//			err := h.Update(msg)
//			if err != nil {
//				return err
//			}
//		}
//	}
//	return nil
//}
//
//func TestProtocol(t *testing.T) {
//	pl := pool.NewPool(0)
//	defer pl.TearDown()
//
//	ids := party.IDSlice{"a", "b", "c"}
//	threshold := 1
//	ps := map[party.ID]*protocol.Handler{}
//
//	wg := new(sync.WaitGroup)
//
//	for _, id := range ids {
//		p, err := protocol.NewHandler(StartKeygen(pl, group, ids, threshold, id))
//		require.NoError(t, err)
//		ps[id] = p
//	}
//	for _, p := range ps {
//		wg.Add(1)
//		go func() {
//			for msg := range p.Listen() {
//				if err := handleMessage(msg, ps); err != nil {
//					t.Fatal(err)
//				}
//			}
//			fmt.Println("done")
//			wg.Done()
//		}()
//	}
//	wg.Wait()
//
//	for _, p := range ps {
//		r, err := p.Result()
//		assert.NoError(t, err)
//		assert.IsType(t, &Result{}, r)
//		res := r.(*Result)
//		assert.NoError(t, res.Config.Validate())
//	}
//
//	newPs := map[party.ID]*protocol.Handler{}
//	for id, p := range ps {
//		r, _ := p.Result()
//		res := r.(*Result)
//		p2, err := protocol.NewHandler(StartRefresh(pl, res.Config))
//		require.NoError(t, err)
//		newPs[id] = p2
//	}
//	ps = newPs
//	for _, p := range ps {
//		wg.Add(1)
//		go getMessages(p)
//	}
//	wg.Wait()
//
//	for _, p := range ps {
//		r, err := p.Result()
//		assert.NoError(t, err)
//		assert.IsType(t, &Result{}, r)
//		res := r.(*Result)
//		assert.NoError(t, res.Config.Validate())
//	}
//}
