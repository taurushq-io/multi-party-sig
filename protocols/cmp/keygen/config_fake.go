package keygen

import (
	"io"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/internal/proto"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

func FakeData(N, T int, source io.Reader) map[party.ID]*Config {
	partyIDs := party.RandomIDs(N)
	configs := make(map[party.ID]*Config, N)
	public := make(map[party.ID]*Public, N)

	f := polynomial.NewPolynomial(T, sample.Scalar(source))
	one := new(safenum.Nat).SetUint64(1)

	rid := newRID()
	_, _ = io.ReadFull(source, rid)

	for _, pid := range partyIDs {
		p, q := sample.Paillier(source)
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
			Secret: &Secret{
				ID:    pid,
				ECDSA: ecdsaSecret,
				P:     &proto.NatMarshaller{Nat: p},
				Q:     &proto.NatMarshaller{Nat: q},
			},
		}
		X := curve.NewIdentityPoint().ScalarBaseMult(ecdsaSecret)
		public[pid] = &Public{
			ECDSA: X,
			N:     n.Big(),
			S:     s.Big(),
			T:     t.Big(),
		}
	}
	return configs
}
