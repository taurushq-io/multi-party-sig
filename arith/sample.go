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
		return nil
	}
	return n
}

func RandomUnit(order *big.Int) *big.Int {
	gcd := new(big.Int)
	one := big.NewInt(1)
	for i := 0; i < 100; i++ {
		n := MustSample(order)
		gcd.GCD(nil, nil, order, n)
		if gcd.Cmp(one) == 0 {
			return n
		}
	}
	panic(errors.New("failed to generate after 100 iters"))
}
