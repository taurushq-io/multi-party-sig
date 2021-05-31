package polynomial

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

type Polynomial struct {
	coefficients []*curve.Scalar
}

// NewPolynomial generates a Polynomial f(X) = secret + a1*X + ... + at*X^t,
// with coefficients in Z_q, and degree t.
func NewPolynomial(degree int, constant *curve.Scalar) *Polynomial {
	var polynomial Polynomial
	polynomial.coefficients = make([]*curve.Scalar, degree+1)

	// SetWithoutSelf the constant term to the secret
	if constant == nil {
		constant = curve.NewScalar()
	}
	polynomial.coefficients[0] = constant

	for i := 1; i <= degree; i++ {
		polynomial.coefficients[i] = curve.NewScalarRandom()
	}

	return &polynomial
}

// Evaluate evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (p *Polynomial) Evaluate(index *curve.Scalar) *curve.Scalar {
	if index.Equal(curve.NewScalar()) {
		panic("attempt to leak secret")
	}

	result := curve.NewScalar()
	// reverse order
	for i := len(p.coefficients) - 1; i >= 0; i-- {
		// b_n-1 = b_n * x + a_n-1
		result.MultiplyAdd(result, index, p.coefficients[i])
	}
	return result

	//x := curve.NewScalar().SetInt64(1)
	//result := curve.NewScalar()
	//for i := 0; i < len(p.coefficients); i++ {
	//	result.MultiplyAdd(x, p.coefficients[i], result)
	//	x.Multiply(x, index)
	//}
	//return result

	//x := scalar.NewScalarUInt32(1)
	//
	//result.Set(edwards25519.NewIdentityPoint())
	//for i := 0; i < len(p.coefficients); i++ {
	//	tmp.VarTimeDoubleScalarBaseMult(x, p.coefficients[i], zero)
	//	result.Add(result, &tmp)
	//
	//	x.Multiply(x, index)
	//}

}

func (p *Polynomial) Constant() *curve.Scalar {
	return p.coefficients[0]
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

// Coefficients returns p's coefficients
func (p *Polynomial) Coefficients() []*curve.Scalar {
	return p.coefficients
}
