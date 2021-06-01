package sample

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

var ErrMaxIters = errors.New("failed to generate after 255 iters")

const maxIters = 255

func mustSample(max *big.Int) *big.Int {
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}
	return n
}

func mustReadBits(buf []byte) {
	var err error
	for i := 0; i < maxIters; i++ {
		if _, err = rand.Read(buf); err == nil {
			return
		}
	}
	panic(ErrMaxIters)
}

// Unit samples a random unit modulo order
func Unit(order *big.Int) *big.Int {
	for i := 0; i < maxIters; i++ {
		n := mustSample(order)
		if arith.IsCoprime(n, order) {
			return n
		}
	}
	panic(ErrMaxIters)
}

// UnitModN returns a u ∈ ℤₙˣ
func UnitModN(n *big.Int) *big.Int {
	var u, gcd big.Int
	one := big.NewInt(1)
	buf := make([]byte, params.PaillierBits/8)
	for i := 0; i < maxIters; i++ {
		mustReadBits(buf)
		u.SetBytes(buf)
		u.Mod(&u, n)
		gcd.GCD(nil, nil, &u, n)
		if gcd.Cmp(one) == 0 {
			return &u
		}
	}
	panic(ErrMaxIters)
}

// QNR samples a random quadratic non-residue in Z_n.
func QNR(n *big.Int) *big.Int {
	var w big.Int
	buf := make([]byte, params.PaillierBits/8)
	for i := 0; i < maxIters; i++ {
		mustReadBits(buf)
		w.SetBytes(buf)
		w.Mod(&w, n)
		if big.Jacobi(&w, n) == -1 {
			return &w
		}
	}
	panic(ErrMaxIters)
}

// BlumPrime returns an odd prime p of size params.BlumPrimeBits,
// such that p == 3 (mod 4)
func BlumPrime() *big.Int {
	// TODO be more flexible on the number of bits in P, Q to avoid square root attack
	for i := uint8(0); i < uint8(255); i++ {
		p, err := rand.Prime(rand.Reader, params.BlumPrimeBits)
		if err != nil {
			continue
		}
		// p == 3 (mod 4)
		//  => p is always odd
		//  => bit 1 is 1
		if p.Bit(1) == 1 {
			return p
		}
	}
	panic(ErrMaxIters)
}

// Paillier generate the necessary integers for a Paillier key pair.
// p, q are Blum primes ( = 3 mod 4)
// n = pq
func Paillier() (p, q *big.Int) {
	p, q = BlumPrime(), BlumPrime()
	return
}

// Pedersen generates the s, t, λ such that s = tˡ
func Pedersen(n, phi *big.Int) (s, t, lambda *big.Int) {
	two := big.NewInt(2)
	// sample lambda without statistical bias
	lambdaBuf := make([]byte, (params.PaillierBits+params.L)/8)
	mustReadBits(lambdaBuf)
	lambda = new(big.Int).SetBytes(lambdaBuf)
	lambda.Mod(lambda, phi)

	tau := UnitModN(n)

	// t = τ² mod N
	t = new(big.Int)
	t.Exp(tau, two, n)

	// s = tˡ mod N
	s = tau
	s.Exp(t, lambda, n)

	return
}
