package keygen

import (
	"fmt"
	mrand "math/rand"
	"reflect"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
)

var roundTypes = []reflect.Type{
	reflect.TypeOf(&round1{}),
	reflect.TypeOf(&round2{}),
	reflect.TypeOf(&round3{}),
	reflect.TypeOf(&round4{}),
	reflect.TypeOf(&output{}),
}

func processRound(t *testing.T, rounds map[party.ID]round.Round, expectedRoundType reflect.Type) {
	N := len(rounds)
	t.Logf("starting round %v", expectedRoundType)
	// get the second set of  messages
	out := make(chan *message.Message, N*N)
	for idJ, r := range rounds {
		require.EqualValues(t, expectedRoundType, reflect.TypeOf(r))
		newRound, err := r.Finalize(out)
		require.NoError(t, err, "failed to generate messages")
		if newRound != nil {
			rounds[idJ] = newRound
		}
	}
	close(out)

	for msg := range out {
		msgBytes, err := cbor.Marshal(msg)
		require.NoError(t, err, "failed to marshal message")
		for idJ, r := range rounds {
			var m message.Message
			require.NoError(t, cbor.Unmarshal(msgBytes, &m), "failed to unmarshal message")
			if m.IsFor(idJ) {
				content := r.MessageContent()
				err = msg.UnmarshalContent(content)
				require.NoError(t, err)
				require.NoError(t, r.VerifyMessage(msg.From, idJ, content))
				require.NoError(t, r.StoreMessage(msg.From, content))
			}
		}
	}

	t.Logf("round %v done", expectedRoundType)
}

func checkOutput(t *testing.T, rounds map[party.ID]round.Round) {
	N := len(rounds)
	newConfigs := make([]*Config, 0, N)
	for _, r := range rounds {
		resultRound := r.(*round.Output)
		result := resultRound.Result.(*Result)
		newConfigs = append(newConfigs, result.Config)
	}

	firstConfig := newConfigs[0]
	pk := firstConfig.PublicKey()
	for _, c := range newConfigs {
		assert.Equal(t, pk, c.PublicKey(), "RID is different")
		assert.Equal(t, firstConfig.RID, c.RID, "RID is different")
		assert.NoError(t, c.Validate(), "failed to validate new config")
	}
}

func TestKeygen(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := 2
	partyIDs := party.RandomIDs(N)

	rounds := make(map[party.ID]round.Round, N)
	for _, partyID := range partyIDs {
		r, _, err := StartKeygen(pl, partyIDs, N-1, partyID)()
		require.NoError(t, err, "round creation should not result in an error")
		rounds[partyID] = r

	}

	for _, roundType := range roundTypes {
		processRound(t, rounds, roundType)
	}
	checkOutput(t, rounds)
}

func TestRefresh(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := 4
	T := N - 1
	configs := FakeData(N, T, mrand.New(mrand.NewSource(1)), pl)

	parties := make(map[party.ID]round.Round, N)
	for partyID, s := range configs {
		r, _, err := StartRefresh(pl, s)()
		require.NoError(t, err, "round creation should not result in an error")
		parties[partyID] = r

	}

	for _, roundType := range roundTypes {
		processRound(t, parties, roundType)
	}
	checkOutput(t, parties)
}

func TestProtocol(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	ids := party.IDSlice{"a", "b"}
	threshold := 1
	ps := map[party.ID]*protocol.Handler{}

	handleMessage := func(msg *message.Message) {
		if msg == nil {
			return
		}
		for id, p := range ps {
			if msg.From == id {
				continue
			}
			if len(msg.To) == 0 || party.IDSlice(msg.To).Contains(id) {
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
		fmt.Println("done")
		wg.Done()
	}

	for _, id := range ids {
		p, err := protocol.NewHandler(StartKeygen(pl, ids, threshold, id))
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
		assert.IsType(t, &Result{}, r)
		res := r.(*Result)
		assert.NoError(t, res.Config.Validate())
	}

	newPs := map[party.ID]*protocol.Handler{}
	for id, p := range ps {
		r, _ := p.Result()
		res := r.(*Result)
		p2, err := protocol.NewHandler(StartRefresh(pl, res.Config))
		require.NoError(t, err)
		newPs[id] = p2
	}
	ps = newPs
	for _, p := range ps {
		wg.Add(1)
		go getMessages(p)
	}
	wg.Wait()

	for _, p := range ps {
		r, err := p.Result()
		assert.NoError(t, err)
		assert.IsType(t, &Result{}, r)
		res := r.(*Result)
		assert.NoError(t, res.Config.Validate())
	}
}
