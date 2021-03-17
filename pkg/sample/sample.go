package sample

import (
	"crypto/rand"
	"errors"
	"math/big"

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
	var gcd big.Int
	for i := uint8(0); i < uint8(255); i++ {
		n := mustSample(order)
		gcd.GCD(nil, nil, order, n)
		if gcd.Cmp(one) == 0 {
			return n
		}
	}
	panic(ErrMaxIters)
}

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

func Paillier() (p, q, n, phi *big.Int) {
	n, phi = big.NewInt(0), big.NewInt(0)

	p = BlumPrime()
	q = BlumPrime()

	phi.Sub(p, one)
	n.Sub(q, one) // n as tmp rec
	phi.Mul(phi, n)

	n.Mul(p, q)
	return
}
