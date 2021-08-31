package keygen

import (
	"io"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

func FakeData(group curve.Curve, N, T int, source io.Reader, pl *pool.Pool) map[party.ID]*Config {
	partyIDs := party.RandomIDs(N)
	configs := make(map[party.ID]*Config, N)
	public := make(map[party.ID]*Public, N)

	f := polynomial.NewPolynomial(group, T, sample.Scalar(source, group))
	one := new(safenum.Nat).SetUint64(1)

	rid := make(RID, params.SecBytes)
	_, _ = io.ReadFull(source, rid)

	for _, pid := range partyIDs {
		p, q := sample.Paillier(source, pl)
		pq := new(safenum.Nat).Mul(p, q, -1)
		n := safenum.ModulusFromNat(pq)
		pMinus1 := new(safenum.Nat).Sub(p, one, -1)
		qMinus1 := new(safenum.Nat).Sub(q, one, -1)
		phi := new(safenum.Nat).Mul(pMinus1, qMinus1, -1)
		s, t, _ := sample.Pedersen(source, phi, n)

		ecdsaSecret := f.Evaluate(pid.Scalar(group))
		configs[pid] = &Config{
			Threshold: uint32(T),
			Public:    NewPublicMap(public),
			RID:       rid.Copy(),
			ID:        pid,
			ECDSA:     ecdsaSecret,
			P:         p,
			Q:         q,
		}
		X := ecdsaSecret.ActOnBase()
		public[pid] = &Public{
			ECDSA: X,
			N:     n,
			S:     s,
			T:     t,
		}
	}
	return configs
}
