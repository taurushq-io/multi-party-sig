package sample

import (
	"io"
	"math/big"

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
