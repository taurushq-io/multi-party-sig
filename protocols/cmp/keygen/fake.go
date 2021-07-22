package keygen

import (
	"crypto/rand"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

func FakeSession(N, T int) (map[party.ID]*Session, map[party.ID]*Secret, error) {
	partyIDs := party.RandomIDs(N)
	public, secrets := FakeData(partyIDs, T)
	var rid RID
	_, _ = rand.Read(rid[:])
	sessions := make(map[party.ID]*Session, N)
	for _, partyID := range partyIDs {
		sid, err := newSID(partyIDs, T)
		if err != nil {
			return nil, nil, err
		}
		s, err := newSession(sid, public, rid)
		if err != nil {
			return nil, nil, err
		}
		sessions[partyID] = s
	}
	return sessions, secrets, nil
}

func FakeData(partyIDs party.IDSlice, threshold int) (map[party.ID]*Public, map[party.ID]*Secret) {
	n := len(partyIDs)
	secrets := make(map[party.ID]*Secret, n)
	public := make(map[party.ID]*Public, n)

	shares, _ := generateShares(partyIDs, threshold)

	for i, pid := range partyIDs {
		sk := paillier.NewSecretKey()
		pail := sk.PublicKey
		ped, _ := sk.GeneratePedersen()

		secrets[pid] = &Secret{
			ID:       pid,
			ECDSA:    shares[i],
			Paillier: sk,
		}
		X := curve.NewIdentityPoint().ScalarBaseMult(shares[i])
		public[pid] = &Public{
			ID:       pid,
			ECDSA:    X,
			Paillier: pail,
			Pedersen: ped,
		}
	}
	return public, secrets
}

func generateShares(parties party.IDSlice, t int) (shares []*curve.Scalar, sum *curve.Scalar) {
	sum = sample.Scalar(rand.Reader)
	f := polynomial.NewPolynomial(t, sum)

	n := len(parties)
	shares = make([]*curve.Scalar, n)
	for i, pid := range parties {
		x := pid.Scalar()
		shares[i] = f.Evaluate(x)
	}
	return
}
