package sample

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

func sampleNeg(buf []byte) ([]byte, bool) {
	mustReadBits(buf)
	signBit := buf[len(buf)-1]&1 == 1
	buf = buf[:len(buf)-2]
	return buf, signBit
}

// IntervalL returns an integer in the range ± 2ˡ.
func IntervalL() *big.Int {
	var n big.Int
	buf, neg := sampleNeg(make([]byte, params.L/8+1))
	n.SetBytes(buf)
	if neg {
		n.Neg(&n)
	}
	return &n
}

// IntervalLPrime returns an integer in the range ± 2ˡº.
func IntervalLPrime() *big.Int {
	var n big.Int
	buf, neg := sampleNeg(make([]byte, params.LPrime/8+1))
	n.SetBytes(buf)
	if neg {
		n.Neg(&n)
	}
	return &n
}

// IntervalLPrime returns an integer in the range ± 2ˡ⁺ᵉ
func IntervalLEps() *big.Int {
	var n big.Int
	buf, neg := sampleNeg(make([]byte, params.LPlusEpsilon/8+1))
	n.SetBytes(buf)
	if neg {
		n.Neg(&n)
	}
	return &n
}

// IntervalLPrimeEps returns an integer in the range ± 2ˡº⁺ᵉ
func IntervalLPrimeEps() *big.Int {
	var n big.Int
	buf, neg := sampleNeg(make([]byte, params.LPrimePlusEpsilon/8+1))
	n.SetBytes(buf)
	if neg {
		n.Neg(&n)
	}
	return &n
}

// IntervalLN returns an integer in the range ± 2ˡ•N, where N is the size of a Paillier modulus.
func IntervalLN() *big.Int {
	var n big.Int
	buf, neg := sampleNeg(make([]byte, (params.L+params.PaillierBits)/8+1))
	n.SetBytes(buf)
	if neg {
		n.Neg(&n)
	}
	return &n
}

// IntervalLEpsN returns an integer in the range ± 2ˡ⁺ᵉ•N, where N is the size of a Paillier modulus.
func IntervalLEpsN() *big.Int {
	var n big.Int
	buf, neg := sampleNeg(make([]byte, (params.LPlusEpsilon+params.PaillierBits)/8+1))
	n.SetBytes(buf)
	if neg {
		n.Neg(&n)
	}
	return &n
}
