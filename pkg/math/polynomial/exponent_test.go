package polynomial

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

func TestExponent_Evaluate(t *testing.T) {
	var lhs curve.Point
	var rhs1, rhs2 curve.Point
	for x := 0; x < 5; x++ {
		N := 1000
		secret := curve.NewScalarRandom()
		poly := NewPolynomial(N, secret)
		polyExp := NewPolynomialExponent(poly)

		randomIndex := curve.NewScalarRandom()

		lhs.ScalarBaseMult(poly.Evaluate(randomIndex))
		polyExp.evaluateHorner(randomIndex, &rhs1)
		polyExp.evaluateClassic(randomIndex, &rhs2)

		assert.Truef(t, lhs.Equal(&rhs1), fmt.Sprint(x))
		assert.Truef(t, lhs.Equal(&rhs2), fmt.Sprint(x))
		assert.Truef(t, rhs1.Equal(&rhs2), fmt.Sprint(x))
	}
}

//func Benchmark_Evaluate(b *testing.B) {
//	N := party.Size(100)
//	secret := curve.NewScalarRandom()
//	poly := NewPolynomial(N, secret)
//	polyExp := NewPolynomialExponent(poly)
//
//	b.Run("normal", func(b *testing.B) {
//		var result curve.Point
//		for i := 0; i < b.N; i++ {
//			randomIndex := party.RandID().Scalar()
//			polyExp.evaluateClassic(randomIndex, &result)
//		}
//	})
//	b.Run("horner", func(b *testing.B) {
//		var result curve.Point
//		for i := 0; i < b.N; i++ {
//			randomIndex := party.RandID().Scalar()
//			polyExp.evaluateHorner(randomIndex, &result)
//		}
//	})
//	b.Run("vartime", func(b *testing.B) {
//		var result curve.Point
//		for i := 0; i < b.N; i++ {
//			randomIndex := party.RandID().Scalar()
//			polyExp.evaluateVar(randomIndex, &result)
//		}
//	})
//}

func TestSum(t *testing.T) {
	N := 20
	Deg := 10

	randomIndex := curve.NewScalarRandom()

	// compute f1(x) + f2(x) + ...
	evaluationScalar := curve.NewScalar()

	// compute F1(x) + F2(x) + ...
	evaluationPartial := curve.NewIdentityPoint()

	polys := make([]*Polynomial, N)
	polysExp := make([]*Exponent, N)
	for i := range polys {
		sec := curve.NewScalarRandom()
		polys[i] = NewPolynomial(Deg, sec)
		polysExp[i] = NewPolynomialExponent(polys[i])

		evaluationScalar.Add(evaluationScalar, polys[i].Evaluate(randomIndex))
		evaluationPartial.Add(evaluationPartial, polysExp[i].Evaluate(randomIndex))
	}

	// compute (F1 + F2 + ...)(x)
	summedExp, _ := Sum(polysExp)
	evaluationSum := summedExp.Evaluate(randomIndex)

	evaluationFromScalar := curve.NewIdentityPoint().ScalarBaseMult(evaluationScalar)
	assert.True(t, evaluationSum.Equal(evaluationFromScalar))
	assert.True(t, evaluationSum.Equal(evaluationPartial))
}
