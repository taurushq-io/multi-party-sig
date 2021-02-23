package arith

import (
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/secp256k1"
)

// Sample returns a randomly sampled integer in the range
// [- 2^maxBits, 2^maxBits].
// If multiplier is not nil, the range is [- 2^bits•multiplier, 2^bits•multiplier].
//
// For memory optimization, we cache the bounds since we know that they are used often.
func Sample(maxBits int, multiplier *big.Int) *big.Int {
	var bound *big.Int
	if multiplier == nil {
		bound = getBound(maxBits)
	} else {
		bound = new(big.Int).Mul(getBound(maxBits), multiplier)
	}
	result, err := rand.Int(rand.Reader, bound)
	if err != nil {
		panic(err)
	}
	negateRand(result)
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
	n.Sub(n, secp256k1.QHalf)
	return n
}