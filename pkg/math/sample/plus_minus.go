package sample

import (
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

// PlusMinus returns a randomly sampled integer in the range
// [- 2^maxBits, 2^maxBits].
// If multiplier is not nil, the range is [- 2^bits•multiplier, 2^bits•multiplier].
//
// For memory optimization, we cache the bounds since we know that they are used often.
func PlusMinus(maxBits int, withN bool) *big.Int {
	if withN {
		maxBits = maxBits + params.PaillierBits
	}

	// add one bit for sign
	bound := getBound(maxBits + 1)

	result, err := rand.Int(rand.Reader, bound)
	if err != nil {
		panic(err)
	}

	shouldNegate := result.Bit(0) == 1
	result.Rsh(result, 1)

	if shouldNegate {
		result.Neg(result)
	}
	return result
}

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
	bitBounds := []int{params.L, params.LPrime, params.L + params.Epsilon, params.LPrime + params.Epsilon}
	for _, bit := range bitBounds {
		getBoundSlow(bit)
		getBoundSlow(bit + params.PaillierBits)
		getBoundSlow(bit + 1)
		getBoundSlow(bit + params.PaillierBits + 1)
	}

	a := bounds
	_ = a[1]
}

// IsInInterval returns true if n ∈ ± 2ᵐᵃˣᵇⁱᵗˢ
func IsInInterval(n *big.Int, maxBits int) bool {
	bound := getBound(maxBits)

	return n.CmpAbs(bound) != 1
}
