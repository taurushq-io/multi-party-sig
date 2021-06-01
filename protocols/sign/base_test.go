package sign

import (
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa"
	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

type testParty struct {
	id    party.ID
	round round.Round

	k, gamma, x, delta, chi, sigma *curve.Scalar
}

func feedMessages(parties []*testParty, msgs []*pb.Message) error {
	for _, msg := range msgs {
		b, err := proto.Marshal(msg)
		if err != nil {
			return err
		}

		for _, p := range parties {
			var m2 pb.Message
			err = proto.Unmarshal(b, &m2)
			if err != nil {
				return err
			}
			if m2.From == p.id {
				continue
			}
			if m2.To != "" && m2.To != p.id {
				continue
			}
			err = p.round.ProcessMessage(&m2)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func TestRound(t *testing.T) {
	N := 5
	T := 3

	message := []byte("hello")
	messageHash := make([]byte, 64)
	sha3.ShakeSum128(messageHash, message)

	sessions := round.FakeSign(N, T, messageHash)
	s1 := sessions[0]

	ecdsaPk := s1.PublicKey
	pk := curve.NewIdentityPoint().SetPublicKey(ecdsaPk)

	x := curve.NewScalar()

	parties := make([]*testParty, 0, T+1)
	for _, s := range sessions {
		r, err := NewRound(s)
		if err != nil {
			t.Error(err)
		}

		x.Add(s.Secret.ECDSA, x)

		parties = append(parties, &testParty{
			id:    s.SelfID(),
			round: r,
		})
	}

	k := curve.NewScalar()
	gamma := curve.NewScalar()
	chi := curve.NewScalar()
	delta := curve.NewScalar()

	// get the first messages
	msgs1 := make([]*pb.Message, 0, N)
	for _, pj := range parties {

		msgs1New, err := pj.round.GenerateMessages()
		if err != nil {
			t.Error(err)
		}

		r, ok := pj.round.(*round1)
		if !ok {
			t.Errorf("not the right round")
		}

		k.Add(k, r.k)
		gamma.Add(gamma, r.gamma)

		msgs1 = append(msgs1, msgs1New...)
		newR, err := pj.round.Finalize()
		if err != nil {
			t.Error(err)
		}
		pj.round = newR
	}

	fmt.Println("R1 done")

	if err := feedMessages(parties, msgs1); err != nil {
		t.Error(err)
		return
	}

	// get the second set of  messages
	msgs2 := make([]*pb.Message, 0, N*N)
	for _, pj := range parties {
		r, ok := pj.round.(*round2)
		if !ok {
			t.Errorf("not the right round")
		}

		msgs2New, err := r.GenerateMessages()
		if err != nil {
			t.Error(err)
		}
		msgs2 = append(msgs2, msgs2New...)

		newR, err := pj.round.Finalize()
		if err != nil {
			t.Error(err)
		}
		pj.round = newR
	}

	fmt.Println("R2 done")

	if err := feedMessages(parties, msgs2); err != nil {
		t.Error(err)
	}

	// get the third set of  messages
	msgs3 := make([]*pb.Message, 0, N*N)
	for _, pj := range parties {
		r, ok := pj.round.(*round3)
		if !ok {
			t.Errorf("not the right round")
		}

		msgs3New, err := r.GenerateMessages()
		if err != nil {
			t.Error(err)
		}

		chi.Add(chi, r.chi)
		delta.Add(delta, r.thisParty.delta)

		msgs3 = append(msgs3, msgs3New...)

		newR, err := pj.round.Finalize()
		if err != nil {
			t.Error(err)
		}
		pj.round = newR
	}

	chi2 := curve.NewScalar().Multiply(x, k)
	if !chi2.Equal(chi) {
		t.Error("chi")
	}

	delta2 := curve.NewScalar().Multiply(gamma, k)
	if !delta2.Equal(delta) {
		t.Error("delta")
	}

	fmt.Println("R3 done")

	if err := feedMessages(parties, msgs3); err != nil {
		t.Error(err)
	}

	// get the second set of  messages
	msgs4 := make([]*pb.Message, 0, N)
	for _, pj := range parties {
		r, ok := pj.round.(*round4)
		if !ok {
			t.Errorf("not the right round")
		}

		msgs4New, err := r.GenerateMessages()
		if err != nil {
			t.Error(err)
		}

		msgs4 = append(msgs4, msgs4New...)

		newR, err := pj.round.Finalize()
		if err != nil {
			t.Error(err)
		}
		pj.round = newR
	}

	fmt.Println("R4 done")

	if err := feedMessages(parties, msgs4); err != nil {
		t.Error(err)
	}

	m := curve.NewScalar().SetHash(messageHash)
	km := curve.NewScalar().Multiply(m, k)
	kInv := curve.NewScalar().Invert(k)
	R := curve.NewIdentityPoint().ScalarBaseMult(kInv)
	rx := R.X()
	sigma := curve.NewScalar().MultiplyAdd(rx, chi, km)
	msgs5 := make([]*pb.Message, 0, N)
	for _, pj := range parties {
		r, ok := pj.round.(*output)
		if !ok {
			t.Errorf("not the right round")
		}

		msgs5New, err := r.GenerateMessages()
		if err != nil {
			t.Error(err)
		}

		msgs5 = append(msgs5, msgs5New...)

		if !r.r.Equal(rx) {
			t.Error("r not the same")
		}

		if !r.R.Equal(R) {
			t.Error("r not the same")
		}

		if !r.signature.R.Equal(R) {
			t.Error("R not the same")
		}

		if !r.signature.S.Equal(sigma) {
			t.Error("sigma not the same")
		}

		if !r.signature.Verify(pk, messageHash) {
			fmt.Println("fail sig")
		}

		// last round returns nil
		newR, err := pj.round.Finalize()
		if err != nil {
			t.Error(err)
		}
		pj.round = newR
	}

	var rModN, sModN secp256k1.ModNScalar
	rModN.SetByteSlice(rx.Bytes())
	sModN.SetByteSlice(sigma.Bytes())
	sig := ecdsa.NewSignature(&rModN, &sModN)
	pkSecp, err := secp256k1.ParsePubKey(pk.BytesCompressed())
	if err != nil {
		t.Error(err)
	}
	if !sig.Verify(messageHash, pkSecp) {
		t.Error("secp fail")
	}
	return
}
