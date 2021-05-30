package polynomial

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

type Polynomial struct {
	coefficients []curve.Scalar
}

// NewPolynomial generates a Polynomial f(X) = secret + a1*X + ... + at*X^t,
// with coefficients in Z_q, and degree t.
func NewPolynomial(degree uint32, constant *curve.Scalar) *Polynomial {
	var polynomial Polynomial
	polynomial.coefficients = make([]curve.Scalar, degree+1)

	// SetWithoutSelf the constant term to the secret
	polynomial.coefficients[0].Set(constant)

	for i := uint32(1); i <= degree; i++ {
		polynomial.coefficients[i].Random()
	}

	return &polynomial
}

// Evaluate evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (p *Polynomial) Evaluate(index *curve.Scalar) *curve.Scalar {
	if index.Equal(curve.NewScalar()) == 1 {
		panic("attempt to leak secret")
	}

	var result curve.Scalar
	// reverse order
	for i := len(p.coefficients) - 1; i >= 0; i-- {
		// b_n-1 = b_n * x + a_n-1
		result.MultiplyAdd(&result, index, &p.coefficients[i])
	}
	return &result
}

func (p *Polynomial) Constant() *curve.Scalar {
	var result curve.Scalar
	result.Set(&p.coefficients[0])
	return &result
}

// Degree is the highest power of the Polynomial
func (p *Polynomial) Degree() uint32 {
	return uint32(len(p.coefficients)) - 1
}

// Size is the number of coefficients of the polynomial
// It is equal to Degree+1
func (p *Polynomial) Size() int {
	return len(p.coefficients)
}

// Reset sets all coefficients to 0
func (p *Polynomial) Reset() {
	zero := curve.NewScalar()
	for i := range p.coefficients {
		p.coefficients[i].Set(zero)
	}
}
