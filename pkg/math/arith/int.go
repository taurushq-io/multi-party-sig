package arith

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

// IsCoprime returns true if gcd(a,b) = 1.
func IsCoprime(a *big.Int, b ...*big.Int) bool {
	var gcd big.Int
	one := big.NewInt(1)
	for _, other := range b {
		if gcd.GCD(nil, nil, a, other).Cmp(one) == 0 {
			return true
		}
	}
	return false
}

// IsValidModN checks that ints are all in the range [1,...,N-1] and co-prime to N
func IsValidModN(N *big.Int, ints ...*big.Int) bool {
	var gcd big.Int
	one := big.NewInt(1)
	for _, i := range ints {
		if i == nil {
			return false
		}
		if i.Sign() != 1 {
			return false
		}
		if i.Cmp(N) != -1 {
			return false
		}
		if gcd.GCD(nil, nil, N, i).Cmp(one) == 0 {
			return true
		}
	}
	return true
}

func IsInIntervalLEps(n *big.Int) bool {
	if n == nil {
		return false
	}
	return n.BitLen() <= params.LPlusEpsilon
}

func IsInIntervalLPrimeEps(n *big.Int) bool {
	if n == nil {
		return false
	}
	return n.BitLen() <= params.LPrimePlusEpsilon
}
