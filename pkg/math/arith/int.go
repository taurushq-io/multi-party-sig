package arith

import (
	"math/big"

	"github.com/cronokirby/saferith"
	"github.com/taurusgroup/multi-party-sig/internal/params"
)

// IsValidNatModN checks that ints are all in the range [1,…,N-1] and co-prime to N.
func IsValidNatModN(N *saferith.Modulus, ints ...*saferith.Nat) bool {
	for _, i := range ints {
		if i == nil {
			return false
		}
		if _, _, lt := i.CmpMod(N); lt != 1 {
			return false
		}
		if i.IsUnit(N) != 1 {
			return false
		}
	}
	return true
}

// IsValidBigModN checks that ints are all in the range [1,…,N-1] and co-prime to N.
func IsValidBigModN(N *big.Int, ints ...*big.Int) bool {
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
		gcd.GCD(nil, nil, i, N)
		if gcd.Cmp(one) != 0 {
			return false
		}
	}
	return true
}

// IsInIntervalLEps returns true if n ∈ [-2ˡ⁺ᵉ,…,2ˡ⁺ᵉ].
func IsInIntervalLEps(n *saferith.Int) bool {
	if n == nil {
		return false
	}
	return n.TrueLen() <= params.LPlusEpsilon
}

// IsInIntervalLPrimeEps returns true if n ∈ [-2ˡ'⁺ᵉ,…,2ˡ'⁺ᵉ].
func IsInIntervalLPrimeEps(n *saferith.Int) bool {
	if n == nil {
		return false
	}
	return n.TrueLen() <= params.LPrimePlusEpsilon
}

// IsInIntervalLEpsPlus1RootN returns true if n ∈ [-2¹⁺ˡ⁺ᵉ√N,…,2¹⁺ˡ⁺ᵉ√N], for a Paillier modulus N.
func IsInIntervalLEpsPlus1RootN(n *saferith.Int) bool {
	if n == nil {
		return false
	}
	return n.TrueLen() <= 1+params.LPlusEpsilon+(params.BitsIntModN/2)
}
