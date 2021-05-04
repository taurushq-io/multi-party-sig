package session

import (
	"fmt"
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

func TestSession_Init(t *testing.T) {
	N := 20
	partyIDs := RandomPartyIDs(N)

	secrets := make(map[party.ID]*Secret, N)

	parties := make(map[party.ID]*Public, N)
	for _, id := range partyIDs {
		parties[id] = &Public{
			ID: id,
		}
		secrets[id] = &Secret{
			ID: id,
		}
	}

	s := Session{
		group:     curve.Curve,
		parties:   partyIDs,
		threshold: N - 1,
		rid:       nil,
		public:    parties,
	}

	if s.state() != StateInit {
		t.Error("bad state")
	}

	if err := s.Validate(nil); err != nil {
		t.Error(err)
	}

	for _, sec := range secrets {
		if err := s.Validate(sec); err != nil {
			t.Error(err)
		}
	}
}

func TestSession_Keygen(t *testing.T) {
	N := 20
	partyIDs := RandomPartyIDs(N)

	secrets := make(map[party.ID]*Secret, N)

	parties := make(map[party.ID]*Public, N)
	for _, id := range partyIDs {
		secret := curve.NewScalarRandom()
		parties[id] = &Public{
			ID:         id,
			ecdsaShare: curve.NewIdentityPoint().ScalarBaseMult(secret),
		}
		secrets[id] = &Secret{
			ID:         id,
			ecdsaShare: secret,
		}
	}

	s := Session{
		group:     curve.Curve,
		parties:   partyIDs,
		threshold: N - 1,
		rid:       make([]byte, params.SecBytes),
		public:    parties,
	}

	if s.state() != StateKeygen {
		t.Error("bad state")
	}

	if err := s.Validate(nil); err != nil {
		t.Error(err)
	}

	for _, sec := range secrets {
		if err := s.Validate(sec); err != nil {
			t.Error(err)
		}
	}
}

func TestSession_Refresh(t *testing.T) {
	N := 5
	partyIDs := RandomPartyIDs(N)

	secrets := make(map[party.ID]*Secret, N)

	parties := make(map[party.ID]*Public, N)
	for _, id := range partyIDs {
		secret := curve.NewScalarRandom()
		p, q, n, phi := sample.Paillier()
		s, T, _ := sample.Pedersen(n, phi)

		parties[id] = &Public{
			ID:         id,
			ecdsaShare: curve.NewIdentityPoint().ScalarBaseMult(secret),
			n:          n,
			s:          s,
			t:          T,
		}

		secrets[id] = &Secret{
			ID:         id,
			ecdsaShare: secret,
			paillierP:  p,
			paillierQ:  q,
		}
	}

	s := Session{
		group:     curve.Curve,
		parties:   partyIDs,
		threshold: N - 1,
		rid:       make([]byte, params.SecBytes),
		public:    parties,
	}

	if s.state() != StateRefresh {
		t.Error("bad state")
	}

	if err := s.Validate(nil); err != nil {
		t.Error(err)
	}

	for _, sec := range secrets {
		if err := s.Validate(sec); err != nil {
			t.Error(err)
		}
	}

	h, err := s.Hash()
	if err != nil {
		t.Error(err)
	}
	o, err := h.ReadBytes(make([]byte, 42))

	if err != nil {
		t.Error(err)
	}
	fmt.Println(o)
}
