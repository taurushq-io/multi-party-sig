package keygen

import (
	"fmt"
	"math/rand"
	"reflect"
	"sync"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

var roundTypes = []reflect.Type{
	reflect.TypeOf(&round1{}),
	reflect.TypeOf(&round2{}),
	reflect.TypeOf(&round3{}),
	reflect.TypeOf(&round4{}),
	reflect.TypeOf(&round5{}),
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
		msgBytes, err := proto.Marshal(msg)
		require.NoError(t, err, "failed to marshal message")
		for idJ, r := range rounds {
			var m message.Message
			require.NoError(t, proto.Unmarshal(msgBytes, &m), "failed to unmarshal message")
			if m.From == idJ {
				continue
			}
			if len(msg.To) == 0 || party.IDSlice(msg.To).Contains(idJ) {
				content := r.MessageContent()
				err = msg.UnmarshalContent(content)
				require.NoError(t, err)
				require.NoError(t, r.ProcessMessage(msg.From, content))
			}
		}
	}

	t.Logf("round %v done", expectedRoundType)
}

func checkOutput(t *testing.T, rounds map[party.ID]round.Round) {
	N := len(rounds)
	// check rid is the same for all
	var rid []byte
	for _, r := range rounds {
		if rid == nil {
			rid = r.(*output).rid[:]
		} else {
			require.EqualValues(t, rid, r.(*output).rid[:], "rhos should be the same")
		}
	}

	newSessions := make([]*Session, 0, N)
	newSecrets := make([]*Secret, 0, N)
	for _, r := range rounds {
		newSessions = append(newSessions, r.(*output).newSession)
		newSecrets = append(newSecrets, r.(*output).newSecret)
	}

	firstSession := newSessions[0]
	for i, s := range newSessions {
		assert.NoError(t, s.ValidateSecret(newSecrets[i]), "failed to validate new session")
		assert.Equal(t, firstSession.SSID(), s.SSID(), "ssid mismatch")
		assert.True(t, newSecrets[i].KeygenDone(), "new session should be in refreshed state")
	}
}

func TestKeygen(t *testing.T) {
	N := 2
	partyIDs := party.RandomIDs(N)

	rounds := make(map[party.ID]round.Round, N)
	for _, partyID := range partyIDs {
		r, _, err := StartKeygen(partyIDs, N-1, partyID)()
		require.NoError(t, err, "round creation should not result in an error")
		rounds[partyID] = r

	}

	for _, roundType := range roundTypes {
		processRound(t, rounds, roundType)
	}
	checkOutput(t, rounds)
}

func TestRefresh(t *testing.T) {

	N := 2
	T := N - 1

	rid := make([]byte, params.SecBytes)
	rand.Read(rid)

	sessions, secrets, err := FakeSession(N, T)
	require.NoError(t, err)

	parties := make(map[party.ID]round.Round, N)
	for partyID, s := range sessions {
		r, _, err := StartRefresh(s, secrets[partyID])()
		require.NoError(t, err, "round creation should not result in an error")
		parties[partyID] = r

	}

	for _, roundType := range roundTypes {
		processRound(t, parties, roundType)
	}
	checkOutput(t, parties)
}

func TestProtocol(t *testing.T) {
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
			fmt.Println("\t\t\tchan", msg)
			handleMessage(msg)
		}
		fmt.Println("done")
		wg.Done()
	}

	for _, id := range ids {
		p, err := protocol.NewHandler(StartKeygen(ids, threshold, id))
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
		err = res.Session.Validate()
		assert.NoError(t, err)
		err = res.Session.ValidateSecret(res.Secret)
		assert.NoError(t, err)
	}

	newPs := map[party.ID]*protocol.Handler{}
	for id, p := range ps {
		r, _ := p.Result()
		res := r.(*Result)
		p2, err := protocol.NewHandler(StartRefresh(res.Session, res.Secret))
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
		err = res.Session.Validate()
		assert.NoError(t, err)
		err = res.Session.ValidateSecret(res.Secret)
		assert.NoError(t, err)
	}
}
