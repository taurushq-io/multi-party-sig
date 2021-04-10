package sample

import (
	"crypto/rand"
	"errors"
	"math/big"
	randInt "math/rand"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

var ErrMaxIters = errors.New("failed to generate after 255 iters")

func mustSample(max *big.Int) *big.Int {
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}
	return n
}

var one = big.NewInt(1)

// Unit samples a random unit modulo order
func Unit(order *big.Int) *big.Int {
	for i := uint8(0); i < uint8(255); i++ {
		n := mustSample(order)
		if arith.IsCoprime(n, order) {
			return n
		}
	}
	panic(ErrMaxIters)
}

// QR returns a quadratic residue mod n=pq, given primes p and q
func QR(n, p, q *big.Int) *big.Int {
	for i := uint8(0); i < uint8(255); i++ {
		w := mustSample(n)
		if big.Jacobi(w, p) == 1 && big.Jacobi(w, q) == 1 {
			return w
		}
	}
	panic(ErrMaxIters)
}

// QNR samples a random quadratic non-residue in Z_n.
func QNR(n *big.Int) *big.Int {
	for i := uint8(0); i < uint8(255); i++ {
		w := mustSample(n)
		if big.Jacobi(w, n) == -1 {
			return w
		}
	}
	panic(ErrMaxIters)
}

// BlumPrime returns an odd prime p of size params.BlumPrimeBits,
// such that p == 3 (mod 4)
func BlumPrime() *big.Int {
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
// phi = (p-1)(q-1)
func Paillier() (p, q, n, phi *big.Int) {
	n, phi = new(big.Int), new(big.Int)

	p, q = BlumPrime(), BlumPrime()

	phi.Sub(p, one)
	n.Sub(q, one) // n as tmp receiver
	phi.Mul(phi, n)

	n.Mul(p, q)
	return
}

var two = big.NewInt(2)

// Pedersen generates the s, t, λ such that s = tˡ
func Pedersen(n, phi *big.Int) (s, t, lambda *big.Int) {
	s, t = new(big.Int), new(big.Int)

	// sample lambda without statistical bias
	lambda = PlusMinus(params.L, true)
	lambda.Mod(lambda, phi)

	tau := Unit(n)

	t.Exp(tau, two, n)
	s.Exp(t, lambda, n)

	return
}

// ID returns a random ID (may be 0)
func ID() uint32 {
	return randInt.Uint32()
}
