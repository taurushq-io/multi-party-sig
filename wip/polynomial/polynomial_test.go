package polynomial

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
)

func TestPolynomial_Constant(t *testing.T) {
	deg := uint32(10)
	secret := curve.NewScalarRandom()
	poly := NewPolynomial(deg, secret)
	require.Equal(t, 1, poly.Constant().Equal(secret))
}

func TestPolynomial_Evaluate(t *testing.T) {
	polynomial := &Polynomial{make([]curve.Scalar, 3)}
	polynomial.coefficients[0].SetInt64(1)
	polynomial.coefficients[2].SetInt64(1)

	for index := uint32(0); index < 100; index++ {
		x := sample.ID()
		max := 1 << 8 * int64(arith.IDByteSize)
		if int64(x) > max {
			continue
		}
		result := 1 + x*x
		computedResult := polynomial.Evaluate(curve.NewScalarUInt(index))
		expectedResult := curve.NewScalarUInt(result)
		require.Equal(t, 1, expectedResult.Equal(computedResult))
	}
}
