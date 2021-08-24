package sample

import (
	"io"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

func sampleNeg(rand io.Reader, bits int) *safenum.Int {
	buf := make([]byte, bits/8+1)
	mustReadBits(rand, buf)
	neg := safenum.Choice(buf[0] & 1)
	buf = buf[1:]
	out := new(safenum.Int).SetBytes(buf)
	out.Neg(neg)
	return out
}

// IntervalL returns an integer in the range ± 2ˡ, but with constant-time properties.
func IntervalL(rand io.Reader) *safenum.Int {
	return sampleNeg(rand, params.L)
}

// IntervalLPrime returns an integer in the range ± 2ˡ', but with constant-time properties.
func IntervalLPrime(rand io.Reader) *safenum.Int {
	return sampleNeg(rand, params.LPrime)
}

// IntervalLEps returns an integer in the range ± 2ˡ⁺ᵉ, but with constant-time properties.
func IntervalLEps(rand io.Reader) *safenum.Int {
	return sampleNeg(rand, params.LPlusEpsilon)
}

// IntervalLPrimeEps returns an integer in the range ± 2ˡ'⁺ᵉ, but with constant-time properties.
func IntervalLPrimeEps(rand io.Reader) *safenum.Int {
	return sampleNeg(rand, params.LPrimePlusEpsilon)
}

// IntervalLN returns an integer in the range ± 2ˡ•N, where N is the size of a Paillier modulus.
func IntervalLN(rand io.Reader) *safenum.Int {
	return sampleNeg(rand, params.L+params.BitsIntModN)
}

// IntervalLEpsN returns an integer in the range ± 2ˡ⁺ᵉ•N, where N is the size of a Paillier modulus.
func IntervalLEpsN(rand io.Reader) *safenum.Int {
	return sampleNeg(rand, params.LPlusEpsilon+params.BitsIntModN)
}

// IntervalScalar returns an integer in the range ±q, with q the size of a Scalar.
func IntervalScalar(rand io.Reader, group curve.Curve) *safenum.Int {
	return sampleNeg(rand, group.ScalarBits())
}
