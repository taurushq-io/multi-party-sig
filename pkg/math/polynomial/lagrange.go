package polynomial

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

// Lagrange returns the Lagrange coefficient
//
// We iterate over all points in the set.
// To get the coefficients over a smaller set,
// you should first get a smaller subset.
//
// The following formulas are taken from
// https://en.wikipedia.org/wiki/Lagrange_polynomial
//			                        x₀ … xₖ
// lⱼ(0) =	--------------------------------------------------
//			-xⱼ⋅(x₀ - xⱼ)⋅⋅⋅(xⱼ₋₁ - xⱼ)⋅(xⱼ₊₁ - xⱼ)⋅⋅⋅(xₖ - xⱼ)
func Lagrange(partyIDs []party.ID) map[party.ID]*curve.Scalar {
	// product = x₀ * … * x_k
	product := curve.NewScalarUInt32(1)
	scalars := make(map[party.ID]*curve.Scalar, len(partyIDs))
	for _, id := range partyIDs {
		xi := id.Scalar()
		scalars[id] = xi
		product.Multiply(product, xi)
	}

	coefficients := make(map[party.ID]*curve.Scalar, len(partyIDs))
	tmp := curve.NewScalar()
	for _, j := range partyIDs {
		xJ := scalars[j]
		// lⱼ = -xⱼ
		lJ := curve.NewScalar().Negate(xJ)

		// lⱼ = -xⱼ⋅(x₀ - xⱼ)⋅⋅⋅(xⱼ₋₁ - xⱼ)⋅(xⱼ₊₁ - xⱼ)⋅⋅⋅(xₖ - xⱼ)
		for _, i := range partyIDs {
			if i == j {
				continue
			}
			// tmp = xⱼ - xᵢ
			xI := scalars[i]
			tmp.Subtract(xJ, xI)
			// lⱼ *= xⱼ - xᵢ
			lJ.Multiply(lJ, tmp)
		}

		lJ.Invert(lJ)
		lJ.Multiply(lJ, product)
		coefficients[j] = lJ
	}
	return coefficients
}
