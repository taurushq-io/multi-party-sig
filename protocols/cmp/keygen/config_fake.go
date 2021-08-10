package keygen

import (
	"io"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

func FakeData(N, T int, source io.Reader, pl *pool.Pool) map[party.ID]*Config {
	partyIDs := party.RandomIDs(N)
	configs := make(map[party.ID]*Config, N)
	public := make(map[party.ID]*Public, N)

	f := polynomial.NewPolynomial(T, sample.Scalar(source))
	one := new(safenum.Nat).SetUint64(1)

	rid := newRID()
	_, _ = io.ReadFull(source, rid)

	for _, pid := range partyIDs {
		p, q := sample.Paillier(source, pl)
		pq := new(safenum.Nat).Mul(p, q, -1)
		n := safenum.ModulusFromNat(pq)
		pMinus1 := new(safenum.Nat).Sub(p, one, -1)
		qMinus1 := new(safenum.Nat).Sub(q, one, -1)
		phi := new(safenum.Nat).Mul(pMinus1, qMinus1, -1)
		s, t, _ := sample.Pedersen(source, phi, n)

		ecdsaSecret := f.Evaluate(pid.Scalar())
		configs[pid] = &Config{
			Threshold: uint32(T),
			Public:    public,
			RID:       rid.Copy(),
			ID:        pid,
			ECDSA:     ecdsaSecret,
			P:         p,
			Q:         q,
		}
		X := curve.NewIdentityPoint().ScalarBaseMult(ecdsaSecret)
		public[pid] = &Public{
			ECDSA: X,
			N:     n,
			S:     s,
			T:     t,
		}
	}
	return configs
}
