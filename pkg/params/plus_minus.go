package params

import (
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
)

// Sample returns a randomly sampled integer in the range
// [- 2^maxBits, 2^maxBits].
// If multiplier is not nil, the range is [- 2^bits•multiplier, 2^bits•multiplier].
//
// For memory optimization, we cache the bounds since we know that they are used often.
func Sample(maxBits int, withN bool) *big.Int {
	if withN {
		maxBits = maxBits + PaillierBits
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

// negateRand sets n to -n with probability 1/2
func negateRand(n *big.Int) {
	var bit [1]byte
	_, _ = rand.Reader.Read(bit[:])
	if (bit[0] & 1) == 0 {
		n.Neg(n)
	}
}

// ModNeg performs modular N reduction on n, but in the interval
// modulusHalf can be nil if it is not readily available, but for efficiency reasons
// it should be provided
func ModNeg(n, modulus, modulusHalf *big.Int) *big.Int {
	if modulusHalf == nil {
		modulusHalf = new(big.Int).Rsh(modulus, 1)
	}
	if n.Cmp(modulus) == 1 {
		n.Mod(n, modulus)
	}
	n.Mod(n, modulus)
	n.Sub(n, curve.QHalf)
	return n
}
