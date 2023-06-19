package sample

import (
	"io"

	"github.com/cronokirby/saferith"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

func sampleNeg(rand io.Reader, bits int) *saferith.Int {
	buf := make([]byte, bits/8+1)
	mustReadBits(rand, buf)
	neg := saferith.Choice(buf[0] & 1)
	buf = buf[1:]
	out := new(saferith.Int).SetBytes(buf)
	out.Neg(neg)
	return out
}

// IntervalL returns an integer in the range ± 2ˡ, but with constant-time properties.
func IntervalL(rand io.Reader) *saferith.Int {
	return sampleNeg(rand, params.L)
}

// IntervalLPrime returns an integer in the range ± 2ˡ', but with constant-time properties.
func IntervalLPrime(rand io.Reader) *saferith.Int {
	return sampleNeg(rand, params.LPrime)
}

// IntervalEps returns an integer in the range ± 2ᵉ, but with constant-time properties.
func IntervalEps(rand io.Reader) *saferith.Int {
	return sampleNeg(rand, params.Epsilon)
}

// IntervalLEps returns an integer in the range ± 2ˡ⁺ᵉ, but with constant-time properties.
func IntervalLEps(rand io.Reader) *saferith.Int {
	return sampleNeg(rand, params.LPlusEpsilon)
}

// IntervalLPrimeEps returns an integer in the range ± 2ˡ'⁺ᵉ, but with constant-time properties.
func IntervalLPrimeEps(rand io.Reader) *saferith.Int {
	return sampleNeg(rand, params.LPrimePlusEpsilon)
}

// IntervalLN returns an integer in the range ± 2ˡ•N, where N is the size of a Paillier modulus.
func IntervalLN(rand io.Reader) *saferith.Int {
	return sampleNeg(rand, params.L+params.BitsIntModN)
}

// IntervalLN2 returns an integer in the range ± 2ˡ•N², where N is the size of a Paillier modulus.
func IntervalLN2(rand io.Reader) *saferith.Int {
	return sampleNeg(rand, params.L+(2*params.BitsIntModN))
}

// IntervalLEpsN returns an integer in the range ± 2ˡ⁺ᵉ•N, where N is the size of a Paillier modulus.
func IntervalLEpsN(rand io.Reader) *saferith.Int {
	return sampleNeg(rand, params.LPlusEpsilon+params.BitsIntModN)
}

// IntervalLEpsN2 returns an integer in the range ± 2ˡ⁺ᵉ•N², where N is the size of a Paillier modulus.
func IntervalLEpsN2(rand io.Reader) *saferith.Int {
	return sampleNeg(rand, params.LPlusEpsilon+(2*params.BitsIntModN))
}

// IntervalLEpsRootN returns an integer in the range ± 2ˡ⁺ᵉ•√N, where N is the size of a Paillier modulus.
func IntervalLEpsRootN(rand io.Reader) *saferith.Int {
	return sampleNeg(rand, params.LPlusEpsilon+(params.BitsIntModN/2))
}

// IntervalScalar returns an integer in the range ±q, with q the size of a Scalar.
func IntervalScalar(rand io.Reader, group curve.Curve) *saferith.Int {
	return sampleNeg(rand, group.ScalarBits())
}
