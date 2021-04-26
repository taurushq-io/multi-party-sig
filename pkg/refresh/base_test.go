package refresh

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
	"google.golang.org/protobuf/proto"
)

type testParty struct {
	idx int
	id  uint32
	p   *Parameters
	c   *session.BaseConfig
	r   round.Round
}

func feedMessages(parties []*testParty, msgs []message.Message) error {
	for _, msg := range msgs {
		m, ok := msg.(*pb.Message)
		if !ok {
			return errors.New("not a pb.Message")
		}
		b, err := proto.Marshal(m)
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
			if m2.To != 0 && m2.To != p.id {
				continue
			}
			err = p.r.ProcessMessage(&m2)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func TestRound(t *testing.T) {
	N := 3
	partyIDs := make(party.IDSlice, N)
	for i := range partyIDs {
		partyIDs[i] = uint32(1 + i*N)
	}
	sort.Sort(partyIDs)

	fullSecret := curve.NewScalar()
	parties := make([]*testParty, N)
	secrets := make([]*curve.Scalar, N)
	publicMap := map[uint32]*curve.Point{}
	for idx, j := range partyIDs {
		secrets[idx] = curve.NewScalarRandom()
		publicMap[j] = curve.NewIdentityPoint().ScalarBaseMult(secrets[idx])
		fullSecret.Add(fullSecret, secrets[idx])
	}
	fullPublic := curve.NewIdentityPoint().ScalarBaseMult(fullSecret)

	for idxJ, j := range partyIDs {
		c, err := session.NewConfig(j, partyIDs)
		if err != nil {
			t.Error(err)
		}

		p := &Parameters{
			PublicSharesECDSA: publicMap,
			PrivateShareECDSA: secrets[idxJ],
		}

		r, err := NewRound(c, p)
		if err != nil {
			t.Error(err)
		}
		parties[idxJ] = &testParty{
			idx: idxJ,
			id:  j,
			p:   p,
			c:   c,
			r:   r,
		}
	}

	// get the first messages
	msgs1 := make([]message.Message, 0, N)
	for _, pj := range parties {
		msgs1New, err := pj.r.GenerateMessages()
		if err != nil {
			t.Error(err)
		}
		msgs1 = append(msgs1, msgs1New...)
		newR, err := pj.r.Finalize()
		if err != nil {
			t.Error(err)
		}
		pj.r = newR
	}

	fmt.Println("R1 done")

	if err := feedMessages(parties, msgs1); err != nil {
		t.Error(err)
	}

	// get the second set of  messages
	msgs2 := make([]message.Message, 0, N*N)
	for _, pj := range parties {
		r, ok := pj.r.(*round2)
		if !ok {
			t.Errorf("not the right round")
		}

		msgs2New, err := r.GenerateMessages()
		if err != nil {
			t.Error(err)
		}
		msgs2 = append(msgs2, msgs2New...)

		newR, err := pj.r.Finalize()
		if err != nil {
			t.Error(err)
		}
		pj.r = newR
	}

	fmt.Println("R2 done")

	if err := feedMessages(parties, msgs2); err != nil {
		t.Error(err)
	}

	fmt.Println("fed msgs from round 2")

	// get the third set of  messages
	msgs3 := make([]message.Message, 0, N*N)
	for _, pj := range parties {
		r, ok := pj.r.(*round3)
		if !ok {
			t.Errorf("not the right round")
		}

		msgs3New, err := r.GenerateMessages()
		if err != nil {
			t.Error(err)
		}
		msgs3 = append(msgs3, msgs3New...)

		newR, err := pj.r.Finalize()
		if err != nil {
			t.Error(err)
		}
		pj.r = newR
	}

	//// check rid is the same for all
	var rho []byte
	for idx, p := range parties {
		if idx == 0 {
			rho = p.r.(*output).rho
		} else {
			if !bytes.Equal(rho, p.r.(*output).rho) {
				t.Error("rho is different")
			}
		}
	}

	fmt.Println("R3 done")

	if err := feedMessages(parties, msgs3); err != nil {
		t.Error(err)
	}

	fmt.Println("fed msgs from round 3")

	// get the second set of  messages
	msgs4 := make([]message.Message, 0, N)
	for _, pj := range parties {
		r, ok := pj.r.(*output)
		if !ok {
			t.Errorf("not the right round")
		}

		msgs4New, err := r.GenerateMessages()
		if err != nil {
			t.Error(err)
		}
		msgs4 = append(msgs4, msgs4New...)

		// last round returns nil
		_, err = pj.r.Finalize()
		if err != nil {
			t.Error(err)
		}
	}

	// check pub key is the same for all
	for _, p := range parties {
		if fullPublic.Equal(p.r.(*output).X) != 1 {
			t.Error("X is different")
		}
	}
}
