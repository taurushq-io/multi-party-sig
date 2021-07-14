package polynomial

import (
	"crypto/rand"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
)

type Polynomial struct {
	Coefficients []curve.Scalar
}

// NewPolynomial generates a Polynomial f(X) = secret + a1*X + … + at*X^t,
// with Coefficient in Z_q, and degree t.
func NewPolynomial(degree int, constant *curve.Scalar) *Polynomial {
	var polynomial Polynomial
	polynomial.Coefficients = make([]curve.Scalar, degree+1)

	// SetWithoutSelf the constant term to the secret
	if constant == nil {
		constant = curve.NewScalar()
	}
	polynomial.Coefficients[0] = *constant

	for i := 1; i <= degree; i++ {
		polynomial.Coefficients[i] = *sample.Scalar(rand.Reader)
	}

	return &polynomial
}

// Evaluate evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (p *Polynomial) Evaluate(index *curve.Scalar) *curve.Scalar {
	if index.IsZero() {
		panic("attempt to leak secret")
	}

	result := curve.NewScalar()
	// reverse order
	for i := len(p.Coefficients) - 1; i >= 0; i-- {
		// bₙ₋₁ = bₙ * x + aₙ₋₁
		result.MultiplyAdd(result, index, &p.Coefficients[i])
	}
	return result
}

func (p *Polynomial) Constant() *curve.Scalar {
	return &p.Coefficients[0]
}

// Degree is the highest power of the Polynomial
func (p *Polynomial) Degree() uint32 {
	return uint32(len(p.Coefficients)) - 1
}
