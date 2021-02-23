package arith

import (
	"crypto/rand"
	"errors"
	"math/big"
)

func MustSample(max *big.Int) *big.Int {
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}
	return n
}

var one = big.NewInt(1)
func RandomUnit(order *big.Int) *big.Int {
	var gcd big.Int
	for i := uint8(0); i < uint8(255); i++ {
		n := MustSample(order)
		gcd.GCD(nil, nil, order, n)
		if gcd.Cmp(one) == 0 {
			return n
		}
	}
	panic(errors.New("failed to generate after 255 iters"))
}
