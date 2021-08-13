package polynomial

import (
	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// Lagrange returns the Lagrange coefficients at 0 for all parties in the interpolation domain.
func Lagrange(group curve.Curve, interpolationDomain []party.ID) map[party.ID]curve.Scalar {
	return LagrangeFor(group, interpolationDomain, interpolationDomain...)
}

// LagrangeFor returns the Lagrange coefficients at 0 for all parties in the given subset.
func LagrangeFor(group curve.Curve, interpolationDomain []party.ID, subset ...party.ID) map[party.ID]curve.Scalar {
	// numerator = x₀ * … * xₖ
	scalars, numerator := getScalarsAndNumerator(group, interpolationDomain)

	coefficients := make(map[party.ID]curve.Scalar, len(subset))
	for _, j := range subset {
		coefficients[j] = lagrange(group, scalars, numerator, j)
	}
	return coefficients
}

// LagrangeSingle returns the lagrange coefficient at 0 of the party with index j.
func LagrangeSingle(group curve.Curve, interpolationDomain []party.ID, j party.ID) curve.Scalar {
	return LagrangeFor(group, interpolationDomain, j)[j]
}

// getScalarsAndNumerator returns the Scalars associated to the list of party.IDs.
func getScalarsAndNumerator(group curve.Curve, interpolationDomain []party.ID) (map[party.ID]curve.Scalar, curve.Scalar) {
	// numerator = x₀ * … * xₖ
	numerator := group.NewScalar().SetNat(new(safenum.Nat).SetUint64(1))
	scalars := make(map[party.ID]curve.Scalar, len(interpolationDomain))
	for _, id := range interpolationDomain {
		xi := id.Scalar(group)
		scalars[id] = xi
		numerator.Mul(xi)
	}
	return scalars, numerator
}

// lagrange returns the Lagrange coefficient lⱼ(0), for j in the interpolation domain.
// The numerator is provided beforehand for efficiency reasons.
//
// The following formulas are taken from
// https://en.wikipedia.org/wiki/Lagrange_polynomial
//			                 x₀ ⋅⋅⋅ xₖ
// lⱼ(0) =	--------------------------------------------------
//			xⱼ⋅(x₀ - xⱼ)⋅⋅⋅(xⱼ₋₁ - xⱼ)⋅(xⱼ₊₁ - xⱼ)⋅⋅⋅(xₖ - xⱼ).
func lagrange(group curve.Curve, interpolationDomain map[party.ID]curve.Scalar, numerator curve.Scalar, j party.ID) curve.Scalar {
	xJ := interpolationDomain[j]
	tmp := group.NewScalar()

	// denominator = xⱼ⋅(xⱼ - x₀)⋅⋅⋅(xⱼ₋₁ - xⱼ)⋅(xⱼ₊₁ - xⱼ)⋅⋅⋅(xₖ - xⱼ)
	denominator := group.NewScalar().SetNat(new(safenum.Nat).SetUint64(1))
	for i, xI := range interpolationDomain {
		if i == j {
			// lⱼ *= xⱼ
			denominator.Mul(xJ)
			continue
		}
		// tmp = xᵢ - xⱼ
		tmp.Set(xJ).Negate().Add(xI)
		// lⱼ *= xᵢ - xⱼ
		denominator.Mul(tmp)
	}

	// lⱼ = numerator/denominator
	lJ := denominator.Invert()
	lJ.Mul(numerator)
	return lJ
}
