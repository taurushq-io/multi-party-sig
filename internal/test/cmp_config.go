package test

import (
	"io"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
)

func GenerateConfig(group curve.Curve, N, T int, source io.Reader, pl *pool.Pool) (map[party.ID]*config.Config, party.IDSlice) {
	partyIDs := PartyIDs(N)
	configs := make(map[party.ID]*config.Config, N)
	public := make(map[party.ID]*config.Public, N)

	f := polynomial.NewPolynomial(group, T, sample.Scalar(source, group))
	one := new(safenum.Nat).SetUint64(1)

	rid, err := types.NewRID(source)
	if err != nil {
		panic(err)
	}

	for _, pid := range partyIDs {
		p, q := sample.Paillier(source, pl)
		pq := new(safenum.Nat).Mul(p, q, -1)
		n := safenum.ModulusFromNat(pq)
		pMinus1 := new(safenum.Nat).Sub(p, one, -1)
		qMinus1 := new(safenum.Nat).Sub(q, one, -1)
		phi := new(safenum.Nat).Mul(pMinus1, qMinus1, -1)
		s, t, _ := sample.Pedersen(source, phi, n)

		elGamalSecret := sample.Scalar(source, group)

		ecdsaSecret := f.Evaluate(pid.Scalar(group))
		configs[pid] = &config.Config{
			Group:     group,
			Threshold: T,
			Public:    public,
			RID:       rid.Copy(),
			ID:        pid,
			ECDSA:     ecdsaSecret,
			ElGamal:   elGamalSecret,
			P:         p,
			Q:         q,
		}
		X := ecdsaSecret.ActOnBase()
		public[pid] = &config.Public{
			ECDSA:   X,
			ElGamal: elGamalSecret.ActOnBase(),
			N:       n,
			S:       s,
			T:       t,
		}
	}
	return configs, partyIDs
}
