package test

import (
	"io"

	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
)

// GenerateConfig creates some random configuration for N parties with set threshold T over the group.
func GenerateConfig(group curve.Curve, N, T int, source io.Reader, pl *pool.Pool) (map[party.ID]*config.Config, party.IDSlice) {
	partyIDs := PartyIDs(N)
	configs := make(map[party.ID]*config.Config, N)
	public := make(map[party.ID]*config.Public, N)

	f := polynomial.NewPolynomial(group, T, sample.Scalar(source, group))

	rid, err := types.NewRID(source)
	if err != nil {
		panic(err)
	}
	chainKey, err := types.NewRID(source)
	if err != nil {
		panic(err)
	}

	for _, pid := range partyIDs {
		paillierSecret := paillier.NewSecretKey(pl)
		s, t, _ := sample.Pedersen(source, paillierSecret.Phi(), paillierSecret.N())
		pedersenPublic := pedersen.New(paillierSecret.Modulus(), s, t)
		elGamalSecret := sample.Scalar(source, group)

		ecdsaSecret := f.Evaluate(pid.Scalar(group))
		configs[pid] = &config.Config{
			Group:     group,
			ID:        pid,
			Threshold: T,
			ECDSA:     ecdsaSecret,
			ElGamal:   elGamalSecret,
			Paillier:  paillierSecret,
			RID:       rid.Copy(),
			ChainKey:  chainKey.Copy(),
			Public:    public,
		}
		X := ecdsaSecret.ActOnBase()
		public[pid] = &config.Public{
			ECDSA:    X,
			ElGamal:  elGamalSecret.ActOnBase(),
			Paillier: paillierSecret.PublicKey,
			Pedersen: pedersenPublic,
		}
	}
	return configs, partyIDs
}
