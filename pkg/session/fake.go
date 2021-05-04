package session

import (
	"math/rand"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

func RandomPartyIDs(n int) party.IDSlice {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	partyIDs := make(party.IDSlice, n)
	for i := range partyIDs {
		b := make([]byte, 20)
		for j := range b {
			b[j] = letters[rand.Intn(len(letters))]
		}
		partyIDs[i] = string(b)
	}
	partyIDs.Sort()
	return partyIDs
}

func FakeInitSession(n, threshold int) (*Session, map[party.ID]*Secret) {
	public := make(map[party.ID]*Public, n)
	secret := make(map[party.ID]*Secret, n)
	parties := RandomPartyIDs(n)
	for _, id := range parties {
		public[id] = &Public{
			ID: id,
		}
		secret[id] = &Secret{
			ID: id,
		}
	}
	session := &Session{
		group:     curve.Curve,
		parties:   parties,
		threshold: threshold,
		public:    public,
	}
	return session, secret
}

func FakeKeygenSession(n, threshold int) (*Session, map[party.ID]*Secret) {
	session, secret := FakeInitSession(n, threshold)

	for _, id := range session.parties {
		share := curve.NewScalarRandom()
		secret[id].ecdsaShare = share
		session.public[id].ecdsaShare = curve.NewIdentityPoint().ScalarBaseMult(share)
	}

	session.rid = make([]byte, params.SecBytes)
	rand.Read(session.rid)

	return session, secret
}

func FakeRefreshSession(n, threshold int) (*Session, map[party.ID]*Secret) {
	session, secret := FakeKeygenSession(n, threshold)

	for _, id := range session.parties {
		p, q, N, phi := sample.Paillier()
		s, t, _ := sample.Pedersen(N, phi)
		secret[id].paillierP = p
		secret[id].paillierQ = q

		session.public[id].n = N
		session.public[id].s = s
		session.public[id].t = t
	}

	return session, secret
}
