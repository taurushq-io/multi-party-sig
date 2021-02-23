package arith

import (
	"math/big"
)

const (
	SecParam = 256
	L        = 1 * SecParam
	LPrime   = 5 * SecParam
	Epsilon  = 2 * SecParam
	LPlusEpsilon  = L + Epsilon
	LPrimePlusEpsilon  = LPrime + Epsilon
)

var bounds map[int]*big.Int

func getBound(bits int) *big.Int {
	b, ok := bounds[bits]
	if ok {
		return b
	}
	var result big.Int
	result.SetBit(&result, bits, 1)
	bounds[bits] = &result
	return &result
}

func init() {
	bounds = map[int]*big.Int{}
	bitBounds := []int{L, LPrime, L + Epsilon, LPrime + Epsilon}
	for _, bit := range bitBounds {
		bounds[bit] = new(big.Int).SetBit(new(big.Int), bit, 1)
	}
}

func IsInInterval(n *big.Int, maxBits int) bool {
	bound := getBound(maxBits)

	return n.CmpAbs(bound) != 1
}