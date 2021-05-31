package polynomial

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

func TestPolynomial_Constant(t *testing.T) {
	deg := 10
	secret := curve.NewScalarRandom()
	poly := NewPolynomial(deg, secret)
	require.True(t, poly.Constant().Equal(secret))
}

func TestPolynomial_Evaluate(t *testing.T) {
	polynomial := &Polynomial{make([]*curve.Scalar, 3)}
	polynomial.coefficients[0] = curve.NewScalar().SetInt64(1)
	polynomial.coefficients[1] = curve.NewScalar()
	polynomial.coefficients[2] = curve.NewScalar().SetInt64(1)

	for index := 0; index < 100; index++ {
		x := rand.Int63n(1 << 8)
		//x := int64(2)
		result := 1 + x*x
		computedResult := polynomial.Evaluate(curve.NewScalar().SetInt64(x))
		expectedResult := curve.NewScalar().SetInt64(result)
		require.True(t, expectedResult.Equal(computedResult))
	}
}
