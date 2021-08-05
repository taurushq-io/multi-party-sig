package polynomial

import (
	"crypto/rand"
	"math/big"
	mrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

func TestPolynomial_Constant(t *testing.T) {
	deg := 10
	secret := sample.Scalar(rand.Reader)
	poly := NewPolynomial(deg, secret)
	require.True(t, poly.Constant().Equal(secret))
}

func TestPolynomial_Evaluate(t *testing.T) {
	polynomial := &Polynomial{make([]curve.Scalar, 3)}
	polynomial.coefficients[0].SetUInt32(1)
	polynomial.coefficients[1].SetUInt32(0)
	polynomial.coefficients[2].SetUInt32(1)

	for index := 0; index < 100; index++ {
		x := mrand.Uint32()
		result := big.NewInt(int64(x))
		result.Mul(result, result)
		result.Add(result, big.NewInt(1))
		computedResult := polynomial.Evaluate(curve.NewScalar().SetUInt32(x))
		expectedResult := curve.NewScalar().SetBigInt(result)
		assert.True(t, expectedResult.Equal(computedResult))
	}
}
