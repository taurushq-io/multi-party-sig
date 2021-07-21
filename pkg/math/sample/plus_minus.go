package sample

import (
	"io"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

func sampleNeg(rand io.Reader, bits int) *big.Int {
	var n big.Int
	buf := make([]byte, bits/8+1)
	mustReadBits(rand, buf)
	neg := buf[0]&1 == 1
	buf = buf[1:]
	n.SetBytes(buf)
	if neg {
		n.Neg(&n)
	}
	return &n
}

// IntervalL returns an integer in the range ± 2ˡ.
func IntervalL(rand io.Reader) *big.Int {
	return sampleNeg(rand, params.L)
}

// IntervalLPrime returns an integer in the range ± 2ˡº.
func IntervalLPrime(rand io.Reader) *big.Int {
	return sampleNeg(rand, params.LPrime)
}

// IntervalLEps returns an integer in the range ± 2ˡ⁺ᵉ
func IntervalLEps(rand io.Reader) *big.Int {
	return sampleNeg(rand, params.LPlusEpsilon)
}

// IntervalLPrimeEps returns an integer in the range ± 2ˡº⁺ᵉ
func IntervalLPrimeEps(rand io.Reader) *big.Int {
	return sampleNeg(rand, params.LPrimePlusEpsilon)
}

// IntervalLN returns an integer in the range ± 2ˡ•N, where N is the size of a Paillier modulus.
func IntervalLN(rand io.Reader) *big.Int {
	return sampleNeg(rand, params.L+params.BitsIntModN)
}

// IntervalLEpsN returns an integer in the range ± 2ˡ⁺ᵉ•N, where N is the size of a Paillier modulus.
func IntervalLEpsN(rand io.Reader) *big.Int {
	return sampleNeg(rand, params.LPlusEpsilon+params.BitsIntModN)
}

// IntervalScalar returns an integer in the range ±q, with q the size of a Scalar
func IntervalScalar(rand io.Reader) *big.Int {
	return sampleNeg(rand, params.BytesScalar*8)
}

func sampleNegSecret(rand io.Reader, bits int) *safenum.Int {
	buf := make([]byte, bits/8+1)
	mustReadBits(rand, buf)
	neg := safenum.Choice(buf[0] & 1)
	buf = buf[1:]
	out := new(safenum.Int).SetBytes(buf)
	out.Neg(neg)
	return out
}

// IntervalL returns an integer in the range ± 2ˡ, but with constant-time properties.
func IntervalLSecret(rand io.Reader) *safenum.Int {
	return sampleNegSecret(rand, params.L)
}

// IntervalLPrime returns an integer in the range ± 2ˡº, but with constant-time properties.
func IntervalLPrimeSecret(rand io.Reader) *safenum.Int {
	return sampleNegSecret(rand, params.LPrime)
}

// IntervalLEps returns an integer in the range ± 2ˡ⁺ᵉ, but with constant-time properties
func IntervalLEpsSecret(rand io.Reader) *safenum.Int {
	return sampleNegSecret(rand, params.LPlusEpsilon)
}

// IntervalLPrimeEps returns an integer in the range ± 2ˡº⁺ᵉ, but with constant-time properties
func IntervalLPrimeEpsSecret(rand io.Reader) *safenum.Int {
	return sampleNegSecret(rand, params.LPrimePlusEpsilon)
}

// IntervalLN returns an integer in the range ± 2ˡ•N, where N is the size of a Paillier modulus.
func IntervalLNSecret(rand io.Reader) *safenum.Int {
	return sampleNegSecret(rand, params.L+params.BitsIntModN)
}

// IntervalLEpsN returns an integer in the range ± 2ˡ⁺ᵉ•N, where N is the size of a Paillier modulus.
func IntervalLEpsNSecret(rand io.Reader) *safenum.Int {
	return sampleNegSecret(rand, params.LPlusEpsilon+params.BitsIntModN)
}
