package session

import (
	"math/rand"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

func GenerateShares(parties party.IDSlice, t int) (shares []*curve.Scalar, sum *curve.Scalar) {
	sum = sample.Scalar()
	f := polynomial.NewPolynomial(t, sum)

	n := len(parties)
	shares = make([]*curve.Scalar, n)
	for i, pid := range parties {
		x := pid.Scalar()
		shares[i] = f.Evaluate(x)
	}
	return
}

func FakeEmpty(n, threshold int) []*BaseSession {
	partyIDs := party.RandomIDs(n)

	secrets := make(map[party.ID]*party.Secret, n)
	public := make(map[party.ID]*party.Public, n)

	for _, pid := range partyIDs {
		secrets[pid] = &party.Secret{
			ID: pid,
		}
		public[pid] = &party.Public{
			ID: pid,
		}
	}

	sessions := make([]*BaseSession, n)
	var err error
	for i, pid := range partyIDs {
		if sessions[i], err = NewBaseSession(partyIDs, threshold, pid); err != nil {
			panic(err)
		}
	}
	return sessions
}

func FakeKeygen(n, threshold int) []*KeygenSession {
	partyIDs := party.RandomIDs(n)

	secrets := make(map[party.ID]*party.Secret, n)
	public := make(map[party.ID]*party.Public, n)

	shares, ecdsaSecret := GenerateShares(partyIDs, threshold)
	ecdsaPublic := curve.NewIdentityPoint().ScalarBaseMult(ecdsaSecret).ToPublicKey()

	rid := make([]byte, params.SecBytes)
	_, _ = rand.Read(rid)

	for i, pid := range partyIDs {
		sk := paillier.NewSecretKey()
		pail := sk.PublicKey
		ped, _ := sk.GeneratePedersen()

		secrets[pid] = &party.Secret{
			ID:       pid,
			ECDSA:    shares[i],
			Paillier: sk,
			RID:      rid,
		}
		X := curve.NewIdentityPoint().ScalarBaseMult(shares[i])
		public[pid] = &party.Public{
			ID:       pid,
			ECDSA:    X,
			Paillier: pail,
			Pedersen: ped,
		}
	}

	sessions := make([]*KeygenSession, n)
	var err error
	for i, pid := range partyIDs {
		if sessions[i], err = NewSession(threshold, public, ecdsaPublic, secrets[pid], nil); err != nil {
			panic(err)
		}
	}
	return sessions
}

func FakeSign(n, threshold int, message []byte) []*SignSession {
	keygenSessions := FakeKeygen(n, threshold)
	parties := keygenSessions[0].PartyIDs()[:threshold+1].Copy()
	sessions := make([]*SignSession, 0, threshold+1)
	for _, s := range keygenSessions {
		if !parties.Contains(s.SelfID()) {
			continue
		}
		s2, err := NewSignSession(s, parties, message)
		if err != nil {
			panic(err)
		}
		sessions = append(sessions, s2)
	}
	return sessions
}
