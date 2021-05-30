package round

import (
	"math/rand"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
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

func FakeInitSession(n, threshold int) (*Session, map[party.ID]*party.Secret) {
	public := make(map[party.ID]*party.Public, n)
	secret := make(map[party.ID]*party.Secret, n)
	parties := RandomPartyIDs(n)
	for _, id := range parties {
		public[id] = &party.Public{
			ID: id,
		}
		secret[id] = &party.Secret{
			ID: id,
		}
	}
	session := &Session{
		group:     curve.Curve,
		parties:   parties,
		threshold: threshold,
		Public:    public,
	}
	return session, secret
}

func FakeKeygenSession(n, threshold int) (*Session, map[party.ID]*party.Secret) {
	session, secret := FakeInitSession(n, threshold)

	for _, id := range session.parties {
		share := curve.NewScalarRandom()

		secret[id].ECDSA = share
		session.Public[id].ECDSA = curve.NewIdentityPoint().ScalarBaseMult(share)
	}

	session.RID = make([]byte, params.SecBytes)
	rand.Read(session.RID)

	return session, secret
}

func FakeRefreshSession(n, threshold int) (*Session, map[party.ID]*party.Secret) {
	session, secret := FakeKeygenSession(n, threshold)

	for _, id := range session.parties {
		_, _, N, phi := sample.Paillier()
		s, t, _ := sample.Pedersen(N, phi)

		pail := paillier.NewPublicKey(N)
		sk := paillier.NewSecretKey(phi, pail)

		secret[id].Paillier = sk

		session.Public[id].Paillier = pail
		session.Public[id].Pedersen = &pedersen.Parameters{
			N: N,
			S: s,
			T: t,
		}
	}

	return session, secret
}
