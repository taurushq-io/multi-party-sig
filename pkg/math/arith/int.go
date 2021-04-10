package arith

import "math/big"

var one = big.NewInt(1)

// IsCoprime returns true if gcd(a,b) = 1.
func IsCoprime(a, b *big.Int) bool {
	var gcd big.Int
	if gcd.GCD(nil, nil, a, b).Cmp(one) == 0 {
		return true
	}
	return false
}
