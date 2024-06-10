package repair

import (
	"crypto/rand"
	"errors"
	"github.com/cronokirby/saferith"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type round1 struct {
	*round.Helper
	// helpers is the IDs of all the helper shares
	// This excludes the ID of the lost share.
	helpers party.IDSlice
	// lostID is the ID of the lost share.
	lostID party.ID
	// privateShare is the secret share of a helper
	// This should be nil for the lost share.
	privateShare *curve.Scalar
}

// VerifyMessage implements round.Round.
//
// Since this is the start of the protocol, we aren't expecting to have received
// any messages yet, so we do nothing.
func (r *round1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round1) StoreMessage(round.Message) error { return nil }

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }

// Finalize implements round.Round.
//
// Round 1 generates delta values from each helper to help the lost share reconstruct its secret.
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	dummyMsg := &message2{r.Group().NewScalar()}
	if r.privateShare == nil {
		// The lost share does nothing until round 3.
		// Library internals, however, require that each share send a message to the other shares
		// before proceeding to round finalization, so we send a dummy message here.
		for _, id := range r.helpers {
			if err := r.SendMessage(out, dummyMsg, id); err != nil {
				return r, err
			}
		}
		return &round2{round1: r}, nil
	}
	group := r.Group()
	randVals := generateCoefficients(group, len(r.helpers)-1)

	// Compute the last delta value given the (generated uniformly at random) remaining ones
	// since they all must add up to `zeta_i * share_i`.
	deltas := make(map[party.ID]curve.Scalar, len(r.helpers))
	for _, id := range r.helpers {
		deltas[id] = group.NewScalar()
	}
	if len(deltas) != len(r.helpers) {
		return nil, errors.New("duplicate party IDs")
	}

	zeta := computeLagrangeCoefficient(group, r.helpers, r.lostID, r.SelfID())
	lhs := group.NewScalar().Set(zeta).Mul(*r.privateShare)
	deltaSum := group.NewScalar()
	for i := range len(r.helpers) - 1 {
		id := r.helpers[i]
		deltas[id].Set(randVals[i])
		deltaSum.Add(randVals[i])
	}
	lastId := r.helpers[len(r.helpers)-1]
	lastVal := group.NewScalar().Set(lhs).Sub(deltaSum)
	deltas[lastId].Set(lastVal)

	for id, delta := range deltas {
		if id == r.SelfID() {
			continue
		}
		if err := r.SendMessage(out, &message2{delta}, id); err != nil {
			return r, err
		}
	}
	// we also need to send a dummy message to the lost share, per library requirements
	if err := r.SendMessage(out, dummyMsg, r.lostID); err != nil {
		return r, err
	}

	r2deltas := make(map[party.ID]curve.Scalar, len(deltas))
	r2deltas[r.SelfID()] = group.NewScalar().Set(deltas[r.SelfID()])

	return &round2{
		round1: r,
		deltas: r2deltas,
	}, nil
}

// generateCoefficients generates random coefficients for secret sharing.
func generateCoefficients(group curve.Curve, n int) []curve.Scalar {
	coefficients := make([]curve.Scalar, n)
	for i := 0; i < n; i++ {
		coefficients[i] = sample.Scalar(rand.Reader, group)
	}
	return coefficients
}

// Compute a lagrange coefficient.
//
// The lagrange functions in the polynomial package only compute Lj(0).
// We need Lj(x) where x is the id of the lost party.
//
// The Lagrange polynomial for a set of points (x_j, y_j) for 0 <= j <= k
// is ∑_{i=0}^k y_i.ℓ_i(x), where ℓ_i(x) is the Lagrange basis polynomial:
//
// ℓ_i(x) = ∏_{0≤j≤k; j≠i} (x - x_j) / (x_i - x_j).
//
// This computes ℓ_j(x) for the set of points `xs` and for the j corresponding
// to the given xj.
func computeLagrangeCoefficient(group curve.Curve, helpers party.IDSlice, lostShare party.ID, selfID party.ID) curve.Scalar {
	num := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))
	den := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))
	x := lostShare.Scalar(group)
	for _, id := range helpers {
		if id == selfID {
			continue
		}
		xj := id.Scalar(group)

		// num *= x - xj
		xminusxj := group.NewScalar().Set(x).Sub(xj)
		num.Mul(xminusxj)

		// den *= xi - xj
		ximinusxj := group.NewScalar().Set(selfID.Scalar(group)).Sub(xj)
		den.Mul(ximinusxj)
	}
	return num.Mul(den.Invert())
}
