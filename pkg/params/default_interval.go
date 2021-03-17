package params

import (
	"math/big"
)

const (
	SecParam          = 256
	StatParam         = 80
	PaillierBits      = 8 * SecParam
	BlumPrimeBits     = 4 * SecParam
	L                 = 1 * SecParam
	LPrime            = 5 * SecParam
	Epsilon           = 2 * SecParam
	LPlusEpsilon      = L + Epsilon
	LPrimePlusEpsilon = LPrime + Epsilon
)

var bounds map[int]*big.Int

func getBoundSlow(bits int) *big.Int {
	var result big.Int
	result.SetBit(&result, bits, 1)
	bounds[bits] = &result
	return &result
}

func getBound(bits int) *big.Int {
	if b, ok := bounds[bits]; ok {
		return b
	}
	return getBoundSlow(bits)
}

func init() {
	bounds = map[int]*big.Int{}
	bitBounds := []int{L, LPrime, L + Epsilon, LPrime + Epsilon}
	for _, bit := range bitBounds {
		getBoundSlow(bit)
		getBoundSlow(bit + PaillierBits)
		getBoundSlow(bit + 1)
		getBoundSlow(bit + PaillierBits + 1)
	}

	a := bounds
	_ = a[1]
}

func IsInInterval(n *big.Int, maxBits int) bool {
	bound := getBound(maxBits)

	return n.CmpAbs(bound) != 1
}
