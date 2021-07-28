package polynomial

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

// Lagrange returns the Lagrange coefficients at 0 for all parties in the interpolation domain.
func Lagrange(interpolationDomain []party.ID) map[party.ID]*curve.Scalar {
	return LagrangeFor(interpolationDomain, interpolationDomain...)
}

// LagrangeFor returns the Lagrange coefficients at 0 for all parties in the given subset.
func LagrangeFor(interpolationDomain []party.ID, subset ...party.ID) map[party.ID]*curve.Scalar {
	// numerator = x₀ * … * xₖ
	scalars, numerator := getScalarsAndNumerator(interpolationDomain)

	coefficients := make(map[party.ID]*curve.Scalar, len(subset))
	for _, j := range subset {
		coefficients[j] = lagrange(scalars, numerator, j)
	}
	return coefficients
}

// LagrangeSingle returns the lagrange coefficient at 0 of the party with index j.
func LagrangeSingle(interpolationDomain []party.ID, j party.ID) *curve.Scalar {
	return LagrangeFor(interpolationDomain, j)[j]
}

// getScalarsAndNumerator returns the Scalars associated to the list of party.IDs
func getScalarsAndNumerator(interpolationDomain []party.ID) (map[party.ID]*curve.Scalar, *curve.Scalar) {
	// numerator = x₀ * … * xₖ
	numerator := curve.NewScalarUInt32(1)
	scalars := make(map[party.ID]*curve.Scalar, len(interpolationDomain))
	for _, id := range interpolationDomain {
		xi := id.Scalar()
		scalars[id] = xi
		numerator.Multiply(numerator, xi)
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
func lagrange(interpolationDomain map[party.ID]*curve.Scalar, numerator *curve.Scalar, j party.ID) *curve.Scalar {
	xJ := interpolationDomain[j]
	tmp := curve.NewScalar()

	// denominator = xⱼ⋅(xⱼ - x₀)⋅⋅⋅(xⱼ₋₁ - xⱼ)⋅(xⱼ₊₁ - xⱼ)⋅⋅⋅(xₖ - xⱼ)
	denominator := curve.NewScalarUInt32(1)
	for i, xI := range interpolationDomain {
		if i == j {
			// lⱼ *= xⱼ
			denominator.Multiply(denominator, xJ)
			continue
		}
		// tmp = xᵢ - xⱼ
		tmp.Subtract(xI, xJ)
		// lⱼ *= xᵢ - xⱼ
		denominator.Multiply(denominator, tmp)
	}

	// lⱼ = numerator/denominator
	lJ := denominator.Invert(denominator)
	lJ.Multiply(lJ, numerator)
	return lJ
}
