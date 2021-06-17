package sample

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

func sampleNeg(bits int) *big.Int {
	var n big.Int
	buf := make([]byte, bits/8+1)
	mustReadBits(buf)
	neg := buf[0]&1 == 1
	buf = buf[1:]
	n.SetBytes(buf)
	if neg {
		n.Neg(&n)
	}
	return &n
}

// IntervalL returns an integer in the range ± 2ˡ.
func IntervalL() *big.Int {
	return sampleNeg(params.L)
}

// IntervalLPrime returns an integer in the range ± 2ˡº.
func IntervalLPrime() *big.Int {
	return sampleNeg(params.LPrime)
}

// IntervalLEps returns an integer in the range ± 2ˡ⁺ᵉ
func IntervalLEps() *big.Int {
	return sampleNeg(params.LPlusEpsilon)
}

// IntervalLPrimeEps returns an integer in the range ± 2ˡº⁺ᵉ
func IntervalLPrimeEps() *big.Int {
	return sampleNeg(params.LPrimePlusEpsilon)
}

// IntervalLN returns an integer in the range ± 2ˡ•N, where N is the size of a Paillier modulus.
func IntervalLN() *big.Int {
	return sampleNeg(params.L + params.BitsIntModN)
}

// IntervalLEpsN returns an integer in the range ± 2ˡ⁺ᵉ•N, where N is the size of a Paillier modulus.
func IntervalLEpsN() *big.Int {
	return sampleNeg(params.LPlusEpsilon + params.BitsIntModN)
}
