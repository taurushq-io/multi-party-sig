package sign

import (
	"reflect"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
	"golang.org/x/crypto/sha3"
)

type testParty struct {
	id party.ID
	r  round.Round

	k, gamma, x, delta, chi, sigma *curve.Scalar
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

func TestRound(t *testing.T) {
	N := 3
	T := 2

	message := []byte("hello")
	messageHash := make([]byte, 64)
	sha3.ShakeSum128(messageHash, message)

	sessions := session.FakeSign(N, T, messageHash)

	x := curve.NewScalar()

	parties := make([]*testParty, 0, T+1)
	for _, s := range sessions {
		r, err := NewRound(s)
		if err != nil {
			t.Error(err)
		}

		x.Add(s.Secret().ECDSA, x)

		parties = append(parties, &testParty{
			id: s.SelfID(),
			r:  r,
		})
	}
	for _, roundType := range roundTypes {
		processRound(t, parties, roundType)
	}

	return
}
