package refresh

import (
	"reflect"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

type testParty struct {
	id party.ID
	r  round.Round
}

var roundTypes = []reflect.Type{
	reflect.TypeOf((*round1)(nil)),
	reflect.TypeOf((*round2)(nil)),
	reflect.TypeOf((*round3)(nil)),
	reflect.TypeOf((*round4)(nil)),
	reflect.TypeOf((*output)(nil)),
}

func processRound(t *testing.T, parties []*testParty, expectedRoundType reflect.Type) {
	N := len(parties)
	t.Logf("starting round %v", expectedRoundType)
	// get the second set of  messages
	outgoingMessages := make([]round.Message, 0, N*N)
	for _, partyJ := range parties {
		require.EqualValues(t, reflect.TypeOf(partyJ.r), expectedRoundType)
		messagesJ, err := partyJ.r.GenerateMessages()
		require.NoError(t, err, "failed to generate messages")

		outgoingMessages = append(outgoingMessages, messagesJ...)

		newRound, err := partyJ.r.Finalize()
		require.NoError(t, err, "failed to generate messages")
		if newRound != nil {
			partyJ.r = newRound
		}
	}

	for _, msg := range outgoingMessages {
		msgBytes, err := proto.Marshal(msg)
		require.NoError(t, err, "failed to marshal message")
		for _, partyJ := range parties {
			var unmarshalledMessage Message
			require.NoError(t, proto.Unmarshal(msgBytes, &unmarshalledMessage), "failed to unmarshal message")
			h := unmarshalledMessage.GetHeader()
			require.NotNilf(t, h, "header is nil")
			if h.From == partyJ.id {
				continue
			}
			if h.To != "" && h.To != partyJ.id {
				continue
			}
			require.NoError(t, partyJ.r.ProcessMessage(&unmarshalledMessage))
		}
	}

	t.Logf("round %v done", expectedRoundType)
}

func checkOutput(t *testing.T, parties []*testParty) {
	N := len(parties)
	//// check rid is the same for all
	var rho []byte
	for idx, p := range parties {
		if idx == 0 {
			rho = p.r.(*output).rho
		} else {
			require.EqualValues(t, rho, p.r.(*output).rho, "rhos should be the same")
		}
	}

	newSessions := make([]session.Session, 0, N)
	for _, p := range parties {
		newSessions = append(newSessions, p.r.(*output).S)
	}

	firstSession := newSessions[0]
	for _, s := range newSessions {
		assert.NoError(t, s.Validate(), "failed to validate new session")
		assert.Equal(t, firstSession.SSID(), s.SSID(), "ssid mismatch")
		assert.True(t, s.Secret().KeygenDone(), "new session should be in refreshed state")
	}
}

func TestKeygen(t *testing.T) {
	N := 3
	sessions := session.FakeEmpty(N, N-1)

	parties := make([]*testParty, N)
	for _, s := range sessions {
		r, err := NewRound(s)
		require.NoError(t, err, "round creation should not result in an error")
		parties[s.SelfIndex()] = &testParty{
			id: s.SelfID(),
			r:  r,
		}
	}

	for _, roundType := range roundTypes {
		processRound(t, parties, roundType)
	}
	checkOutput(t, parties)
}

func TestRefresh(t *testing.T) {
	N := 3
	//sessions := session.FakeEmpty(N, N-1)
	sessions := session.FakeKeygen(N, N-1)

	parties := make([]*testParty, N)
	for _, s := range sessions {
		r, err := NewRound(s)
		require.NoError(t, err, "round creation should not result in an error")
		parties[s.SelfIndex()] = &testParty{
			id: s.SelfID(),
			r:  r,
		}
	}

	for _, roundType := range roundTypes {
		processRound(t, parties, roundType)
	}
	checkOutput(t, parties)
}
