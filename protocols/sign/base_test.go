package sign

import (
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
	"golang.org/x/crypto/sha3"
)

type testParty struct {
	r round.Round

	k, gamma, x, delta, chi, sigma *curve.Scalar
}

var roundTypes = []reflect.Type{
	reflect.TypeOf(&round1{}),
	reflect.TypeOf(&round2{}),
	reflect.TypeOf(&round3{}),
	reflect.TypeOf(&round4{}),
	reflect.TypeOf(&output{}),
}

func processRound(t *testing.T, parties map[party.ID]*testParty, expectedRoundType reflect.Type) {
	N := len(parties)
	t.Logf("starting round %v", expectedRoundType)
	// get the second set of  messages
	out := make(chan *round.Message, N*N)
	for _, partyJ := range parties {
		assert.EqualValues(t, expectedRoundType, reflect.TypeOf(partyJ.r))
		err := partyJ.r.GenerateMessages(out)
		require.NoError(t, err, "failed to generate messages")

		switch r := partyJ.r.(type) {
		case *round1:
			partyJ.k = r.KShare
			partyJ.gamma = r.GammaShare
			partyJ.x = r.Secret.ECDSA
		case *round2:
		case *round3:
			partyJ.chi = r.ChiShare
		case *round4:
		case *output:

		}

		newRound := partyJ.r.Next()
		require.NoError(t, err, "failed to generate messages")
		if newRound != nil {
			partyJ.r = newRound
		}
	}
	close(out)

	for msg := range out {
		msgBytes, err := proto.Marshal(msg)
		require.NoError(t, err, "failed to marshal message")
		for idJ, partyJ := range parties {
			var m round.Message
			require.NoError(t, proto.Unmarshal(msgBytes, &m), "failed to unmarshal message")
			if m.From == idJ {
				continue
			}
			if len(m.To) == 0 || party.IDSlice(m.To).Contains(idJ) {
				content := partyJ.r.MessageContent()
				err = msg.UnmarshalContent(content)
				require.NoError(t, err)
				require.NoError(t, partyJ.r.ProcessMessage(msg.From, content))
			}

		}
	}

	t.Logf("round %v done", expectedRoundType)
}

func TestRound(t *testing.T) {
	N := 2
	T := 1

	rid := make([]byte, params.SecBytes)
	_, _ = rand.Read(rid)

	t.Log("generating sessions")
	sessions, secrets, err := session.FakeSession(N, T)
	require.NoError(t, err)
	partyIDs := make([]party.ID, 0, T+1)
	for id := range sessions {
		partyIDs = append(partyIDs, id)
		if len(partyIDs) == T+1 {
			break
		}
	}
	t.Log("done generating sessions")

	message := []byte("hello")
	messageHash := make([]byte, 64)
	sha3.ShakeSum128(messageHash, message)

	parties := make(map[party.ID]*testParty, N)
	for _, partyID := range partyIDs {
		s := sessions[partyID]
		r, _, err := StartSign(s, secrets[partyID], partyIDs, messageHash)()
		require.NoError(t, err, "round creation should not result in an error")
		parties[partyID] = &testParty{r: r}
	}

	for _, roundType := range roundTypes {
		processRound(t, parties, roundType)
	}

	return
}
