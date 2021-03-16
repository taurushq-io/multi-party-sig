package polynomial

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

func TestPolynomial_Constant(t *testing.T) {
	deg := party.Size(10)
	secret := curve.NewScalarRandom()
	poly := NewPolynomial(deg, secret)
	require.Equal(t, 1, poly.Constant().Equal(secret))
}

func TestPolynomial_Evaluate(t *testing.T) {
	polynomial := &Polynomial{make([]curve.Scalar, 3)}
	polynomial.coefficients[0].SetInt64(1)
	polynomial.coefficients[2].SetInt64(1)

	for index := uint32(0); index < 100; index++ {
		x := party.RandID()
		max := 1 << 8 * int64(party.ByteSize)
		if int64(x) > max {
			continue
		}
		result := 1 + x*x
		computedResult := polynomial.Evaluate(party.ID(index).Scalar())
		expectedResult := result.Scalar()
		require.Equal(t, 1, expectedResult.Equal(computedResult))
	}
}
