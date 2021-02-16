package zk

import "math/big"

const (
	L      = 256
	LPrime = 1280
	Eps    = 512
)

var (
	TwoPowL         = new(big.Int).SetBit(new(big.Int), L, 1)
	TwoPowLPrime    = new(big.Int).SetBit(new(big.Int), LPrime, 1)
	TwoPowLEps      = new(big.Int).SetBit(new(big.Int), L+Eps, 1)
	TwoPowLPrimeEps = new(big.Int).SetBit(new(big.Int), LPrime+Eps, 1)
)
