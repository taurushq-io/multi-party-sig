package arith

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

var one = big.NewInt(1)

// IsCoprime returns true if gcd(a,b) = 1.
func IsCoprime(a, b *big.Int) bool {
	var gcd big.Int
	if gcd.GCD(nil, nil, a, b).Cmp(one) == 0 {
		return true
	}
	return false
}

func IsInIntervalLEps(n *big.Int) bool {
	return n.BitLen() < params.LPlusEpsilon
}

func IsInIntervalLPrimeEps(n *big.Int) bool {
	return n.BitLen() < params.LPrimePlusEpsilon
}
