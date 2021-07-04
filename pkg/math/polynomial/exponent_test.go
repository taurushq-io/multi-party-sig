package polynomial

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
)

func TestExponent_Evaluate(t *testing.T) {
	var lhs curve.Point
	for x := 0; x < 5; x++ {
		N := 1000
		var secret *curve.Scalar
		if x%2 == 0 {
			secret = sample.Scalar()
		}
		poly := NewPolynomial(N, secret)
		polyExp := NewPolynomialExponent(poly)

		randomIndex := sample.Scalar()

		lhs.ScalarBaseMult(poly.Evaluate(randomIndex))
		rhs1 := polyExp.evaluateHorner(randomIndex)
		rhs2 := polyExp.evaluateClassic(randomIndex)

		assert.Truef(t, lhs.Equal(rhs1), fmt.Sprint("base eval differs from horner", x))
		assert.Truef(t, lhs.Equal(rhs2), fmt.Sprint("base eval differs from classic", x))
		assert.Truef(t, rhs1.Equal(rhs2), fmt.Sprint("horner differs from classic", x))
	}
}

func TestSum(t *testing.T) {
	N := 20
	Deg := 10

	randomIndex := sample.Scalar()

	// compute f1(x) + f2(x) + …
	evaluationScalar := curve.NewScalar()

	// compute F1(x) + F2(x) + …
	evaluationPartial := curve.NewIdentityPoint()

	polys := make([]*Polynomial, N)
	polysExp := make([]*Exponent, N)
	for i := range polys {
		sec := sample.Scalar()
		polys[i] = NewPolynomial(Deg, sec)
		polysExp[i] = NewPolynomialExponent(polys[i])

		evaluationScalar.Add(evaluationScalar, polys[i].Evaluate(randomIndex))
		evaluationPartial.Add(evaluationPartial, polysExp[i].Evaluate(randomIndex))
	}

	// compute (F1 + F2 + …)(x)
	summedExp, _ := Sum(polysExp)
	evaluationSum := summedExp.Evaluate(randomIndex)

	evaluationFromScalar := curve.NewIdentityPoint().ScalarBaseMult(evaluationScalar)
	assert.True(t, evaluationSum.Equal(evaluationFromScalar))
	assert.True(t, evaluationSum.Equal(evaluationPartial))
}
