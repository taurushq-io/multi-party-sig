package round

import (
	"fmt"
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

func TestSession_Init(t *testing.T) {
	N := 20
	partyIDs := RandomPartyIDs(N)

	secrets := make(map[party.ID]*party.Secret, N)

	parties := make(map[party.ID]*party.Public, N)
	for _, id := range partyIDs {
		parties[id] = party.NewPublic(id, nil, nil)
		secrets[id] = party.NewSecret(id, nil, nil, nil)
	}

	s := Session{
		group:     curve.Curve,
		parties:   partyIDs,
		threshold: N - 1,
		RID:       nil,
		Public:    parties,
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

	secrets := make(map[party.ID]*party.Secret, N)

	parties := make(map[party.ID]*party.Public, N)
	for _, id := range partyIDs {
		secret := curve.NewScalarRandom()
		parties[id] = party.NewPublic(id, curve.NewIdentityPoint().ScalarBaseMult(secret), nil)
		secrets[id] = party.NewSecret(id, secret, nil, nil)
	}

	s := Session{
		group:     curve.Curve,
		parties:   partyIDs,
		threshold: N - 1,
		RID:       make([]byte, params.SecBytes),
		Public:    parties,
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

	secrets := make(map[party.ID]*party.Secret, N)

	parties := make(map[party.ID]*party.Public, N)
	for _, id := range partyIDs {
		secret := curve.NewScalarRandom()
		p, q, n, phi := sample.Paillier()
		s, T, _ := sample.Pedersen(n, phi)

		parties[id] = party.NewPublic(id, curve.NewIdentityPoint().ScalarBaseMult(secret), &pedersen.Parameters{
			N: n,
			S: s,
			T: T,
		})
		secrets[id] = party.NewSecret(id, secret, p, q)
	}

	s := Session{
		group:     curve.Curve,
		parties:   partyIDs,
		threshold: N - 1,
		RID:       make([]byte, params.SecBytes),
		Public:    parties,
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
