package polynomial

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

// evaluateClassic evaluates a polynomial in a given variable index
// We do the classic method, where we compute all powers of x.
func (p *Exponent) evaluateClassic(x curve.Scalar) curve.Point {
	var tmp curve.Point

	xPower := p.group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))
	result := p.group.NewPoint()

	if p.IsConstant {
		// since we start at index 1 of the polynomial, x must be x and not 1
		xPower.Mul(x)
	}

	for i := 0; i < len(p.coefficients); i++ {
		// tmp = [xⁱ]Aᵢ
		tmp = xPower.Act(p.coefficients[i])
		// result += [xⁱ]Aᵢ
		result = result.Add(tmp)
		// x = xⁱ⁺¹
		xPower.Mul(x)
	}
	return result
}

func TestExponent_Evaluate(t *testing.T) {
	group := curve.Secp256k1{}

	var lhs curve.Point
	for x := 0; x < 5; x++ {
		N := 1000
		secret := group.NewScalar()
		if x%2 == 0 {
			secret = sample.Scalar(rand.Reader, group)
		}
		poly := NewPolynomial(group, N, secret)
		polyExp := NewPolynomialExponent(poly)

		randomIndex := sample.Scalar(rand.Reader, group)

		lhs = poly.Evaluate(randomIndex).ActOnBase()
		rhs1 := polyExp.Evaluate(randomIndex)
		rhs2 := polyExp.evaluateClassic(randomIndex)

		require.Truef(t, lhs.Equal(rhs1), fmt.Sprint("base eval differs from horner", x))
		require.Truef(t, lhs.Equal(rhs2), fmt.Sprint("base eval differs from classic", x))
		require.Truef(t, rhs1.Equal(rhs2), fmt.Sprint("horner differs from classic", x))
	}
}

func TestSum(t *testing.T) {
	group := curve.Secp256k1{}

	N := 20
	Deg := 10

	randomIndex := sample.Scalar(rand.Reader, group)

	// compute f1(x) + f2(x) + …
	evaluationScalar := group.NewScalar()

	// compute F1(x) + F2(x) + …
	evaluationPartial := group.NewPoint()

	polys := make([]*Polynomial, N)
	polysExp := make([]*Exponent, N)
	for i := range polys {
		sec := sample.Scalar(rand.Reader, group)
		polys[i] = NewPolynomial(group, Deg, sec)
		polysExp[i] = NewPolynomialExponent(polys[i])

		evaluationScalar.Add(polys[i].Evaluate(randomIndex))
		evaluationPartial = evaluationPartial.Add(polysExp[i].Evaluate(randomIndex))
	}

	// compute (F1 + F2 + …)(x)
	summedExp, _ := Sum(polysExp)
	evaluationSum := summedExp.Evaluate(randomIndex)

	evaluationFromScalar := evaluationScalar.ActOnBase()
	assert.True(t, evaluationSum.Equal(evaluationFromScalar))
	assert.True(t, evaluationSum.Equal(evaluationPartial))
}

func TestMarshall(t *testing.T) {
	group := curve.Secp256k1{}

	sec := sample.Scalar(rand.Reader, group)
	poly := NewPolynomial(group, 10, sec)
	polyExp := NewPolynomialExponent(poly)
	out, err := cbor.Marshal(polyExp)
	require.NoError(t, err, "failed to Marshal")
	polyExp2 := EmptyExponent(group)
	err = cbor.Unmarshal(out, polyExp2)
	require.NoError(t, err, "failed to Unmarshal")
	assert.True(t, polyExp.Equal(*polyExp2), "should be the same")
}
