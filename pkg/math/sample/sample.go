package sample

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

var ErrMaxIters = errors.New("failed to generate after 255 iters")

const maxIters = 255

func mustReadBits(buf []byte) {
	var err error
	for i := 0; i < maxIters; i++ {
		if _, err = rand.Read(buf); err == nil {
			return
		}
	}
	panic(ErrMaxIters)
}

// UnitModN returns a u ∈ ℤₙˣ
func UnitModN(n *big.Int) *big.Int {
	var u, gcd big.Int
	one := big.NewInt(1)
	buf := make([]byte, params.BitsIntModN/8)
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
	buf := make([]byte, params.BitsIntModN/8)
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

// BlumPrime returns an odd prime p of size params.BitsBlumPrime,
// such that p == 3 (mod 4)
func BlumPrime() *big.Int {
	// TODO be more flexible on the number of bits in P, Q to avoid square root attack
	for i := uint8(0); i < uint8(255); i++ {
		p, err := rand.Prime(rand.Reader, params.BitsBlumPrime)
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
	lambdaBuf := make([]byte, (params.BitsIntModN+params.L)/8)
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

func Scalar() *curve.Scalar {
	var s curve.Scalar
	buffer := make([]byte, params.BytesScalar)
	mustReadBits(buffer)
	s.SetBytes(buffer)
	return &s
}

func ScalarPointPair() (*curve.Scalar, *curve.Point) {
	var p curve.Point
	s := Scalar()
	p.ScalarBaseMult(s)
	return s, &p
}
