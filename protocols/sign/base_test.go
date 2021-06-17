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
	//s1 := sessions[0]

	//ecdsaPk := s1.PublicKey()
	//pk := curve.FromPublicKey(ecdsaPk)

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

	//var rModN, sModN secp256k1.ModNScalar
	//rModN.SetByteSlice(rx.Bytes())
	//sModN.SetByteSlice(sigma.Bytes())
	//sig := ecdsa.NewSignature(&rModN, &sModN)
	//pkSecp, err := secp256k1.ParsePubKey(pk.BytesCompressed())
	//if err != nil {
	//	t.Error(err)
	//}
	//if !sig.Verify(messageHash, pkSecp) {
	//	t.Error("secp fail")
	//}

	//k := curve.NewScalar()
	//gamma := curve.NewScalar()
	//chi := curve.NewScalar()
	//delta := curve.NewScalar()
	//
	//// get the first messages
	//msgs1 := make([]*proto2.Message, 0, N)
	//for _, pj := range parties {
	//
	//	msgs1New, err := pj.round.GenerateMessages()
	//	if err != nil {
	//		t.Error(err)
	//	}
	//
	//	r, ok := pj.round.(*round1)
	//	if !ok {
	//		t.Errorf("not the right round")
	//	}
	//
	//	k.Add(k, r.KShare)
	//	gamma.Add(gamma, r.GammaShare)
	//
	//	msgs1 = append(msgs1, msgs1New...)
	//	newR, err := pj.round.Finalize()
	//	if err != nil {
	//		t.Error(err)
	//	}
	//	pj.round = newR
	//}
	//
	//fmt.Println("R1 done")
	//
	//if err := feedMessages(parties, msgs1); err != nil {
	//	t.Error(err)
	//	return
	//}
	//
	//// get the second set of  messages
	//msgs2 := make([]*proto2.Message, 0, N*N)
	//for _, pj := range parties {
	//	r, ok := pj.round.(*round2)
	//	if !ok {
	//		t.Errorf("not the right round")
	//	}
	//
	//	msgs2New, err := r.GenerateMessages()
	//	if err != nil {
	//		t.Error(err)
	//	}
	//	msgs2 = append(msgs2, msgs2New...)
	//
	//	newR, err := pj.round.Finalize()
	//	if err != nil {
	//		t.Error(err)
	//	}
	//	pj.round = newR
	//}
	//
	//fmt.Println("R2 done")
	//
	//if err := feedMessages(parties, msgs2); err != nil {
	//	t.Error(err)
	//}
	//
	//// get the third set of  messages
	//msgs3 := make([]*proto2.Message, 0, N*N)
	//for _, pj := range parties {
	//	r, ok := pj.round.(*round3)
	//	if !ok {
	//		t.Errorf("not the right round")
	//	}
	//
	//	msgs3New, err := r.GenerateMessages()
	//	if err != nil {
	//		t.Error(err)
	//	}
	//
	//	chi.Add(chi, r.ChiShare)
	//	delta.Add(delta, r.Self.DeltaShare)
	//
	//	msgs3 = append(msgs3, msgs3New...)
	//
	//	newR, err := pj.round.Finalize()
	//	if err != nil {
	//		t.Error(err)
	//	}
	//	pj.round = newR
	//}
	//
	//chi2 := curve.NewScalar().Multiply(x, k)
	//if !chi2.Equal(chi) {
	//	t.Error("ChiShare")
	//}
	//
	//delta2 := curve.NewScalar().Multiply(gamma, k)
	//if !delta2.Equal(delta) {
	//	t.Error("DeltaShare")
	//}
	//
	//fmt.Println("R3 done")
	//
	//if err := feedMessages(parties, msgs3); err != nil {
	//	t.Error(err)
	//}
	//
	//// get the second set of  messages
	//msgs4 := make([]*proto2.Message, 0, N)
	//for _, pj := range parties {
	//	r, ok := pj.round.(*round4)
	//	if !ok {
	//		t.Errorf("not the right round")
	//	}
	//
	//	msgs4New, err := r.GenerateMessages()
	//	if err != nil {
	//		t.Error(err)
	//	}
	//
	//	msgs4 = append(msgs4, msgs4New...)
	//
	//	newR, err := pj.round.Finalize()
	//	if err != nil {
	//		t.Error(err)
	//	}
	//	pj.round = newR
	//}
	//
	//fmt.Println("R4 done")
	//
	//if err := feedMessages(parties, msgs4); err != nil {
	//	t.Error(err)
	//}
	//
	//m := curve.NewScalar().SetHash(messageHash)
	//km := curve.NewScalar().Multiply(m, k)
	//kInv := curve.NewScalar().Invert(k)
	//R := curve.NewIdentityPoint().ScalarBaseMult(kInv)
	//rx := R.XScalar()
	//sigma := curve.NewScalar().MultiplyAdd(rx, chi, km)
	//msgs5 := make([]*proto2.Message, 0, N)
	//for _, pj := range parties {
	//	r, ok := pj.round.(*output)
	//	if !ok {
	//		t.Errorf("not the right round")
	//	}
	//
	//	msgs5New, err := r.GenerateMessages()
	//	if err != nil {
	//		t.Error(err)
	//	}
	//
	//	msgs5 = append(msgs5, msgs5New...)
	//
	//	if !r.r.Equal(rx) {
	//		t.Error("r not the same")
	//	}
	//
	//	if !r.R.Equal(R) {
	//		t.Error("r not the same")
	//	}
	//
	//	if !r.signature.R.Equal(R) {
	//		t.Error("R not the same")
	//	}
	//
	//	if !r.signature.S.Equal(sigma) {
	//		t.Error("SigmaShare not the same")
	//	}
	//
	//	if !r.signature.Verify(pk, messageHash) {
	//		fmt.Println("fail sig")
	//	}
	//
	//	// last round returns nil
	//	newR, err := pj.round.Finalize()
	//	if err != nil {
	//		t.Error(err)
	//	}
	//	pj.round = newR
	//}

	return
}
