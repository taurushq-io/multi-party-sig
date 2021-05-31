package round

import (
	"math/rand"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

func GenerateShares(parties party.IDSlice, t int) (shares []*curve.Scalar, sum *curve.Scalar) {
	sum = curve.NewScalarRandom()
	f := polynomial.NewPolynomial(t, sum)

	n := len(parties)
	shares = make([]*curve.Scalar, n)
	for i, pid := range parties {
		x := curve.NewScalar().SetBytes([]byte(pid))
		shares[i] = f.Evaluate(x)
	}
	return
}

func FakeKeygen(n, threshold int) []*Session {
	partyIDs := party.RandomPartyIDs(n)

	secrets := make(map[party.ID]*party.Secret, n)
	public := make(map[party.ID]*party.Public, n)

	shares, ecdsaSecret := GenerateShares(partyIDs, threshold)
	ecdsaPublic := curve.NewIdentityPoint().ScalarBaseMult(ecdsaSecret).ToPublicKey()

	rid := make([]byte, params.SecBytes)
	_, _ = rand.Read(rid)

	for i, pid := range partyIDs {
		sk := paillier.NewSecretKey()
		pail := sk.PublicKey()
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

	sessions := make([]*Session, n)
	for i, pid := range partyIDs {
		sessions[i] = &Session{
			group:     curve.Curve,
			Parties:   partyIDs,
			Threshold: threshold,
			Public:    public,
			Secret:    secrets[pid],
			PublicKey: ecdsaPublic,
		}
		ssid, err := sessions[i].RecomputeSSID()
		if err != nil {
			panic(err)
		}
		sessions[i].SetSSID(ssid)
	}
	return sessions
}

//func RandomPartyIDs(n int) party.IDSlice {
//	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
//
//	partyIDs := make(party.IDSlice, n)
//	for i := range partyIDs {
//		b := make([]byte, 20)
//		for j := range b {
//			b[j] = letters[rand.Intn(len(letters))]
//		}
//		partyIDs[i] = string(b)
//	}
//	partyIDs.Sort()
//	return partyIDs
//}
