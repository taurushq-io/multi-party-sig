package sample

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

var ErrMaxIterations = errors.New("failed to generate after 255 iterations")

const maxIterations = 255

func mustReadBits(buf []byte) {
	var err error
	for i := 0; i < maxIterations; i++ {
		if _, err = rand.Read(buf); err == nil {
			return
		}
	}
	panic(ErrMaxIterations)
}

// UnitModN returns a u ∈ ℤₙˣ
func UnitModN(n *big.Int) *big.Int {
	var u, gcd big.Int
	one := big.NewInt(1)
	buf := make([]byte, params.BitsIntModN/8)
	for i := 0; i < maxIterations; i++ {
		mustReadBits(buf)
		u.SetBytes(buf)
		u.Mod(&u, n)
		gcd.GCD(nil, nil, &u, n)
		if gcd.Cmp(one) == 0 {
			return &u
		}
	}
	panic(ErrMaxIterations)
}

// QNR samples a random quadratic non-residue in Z_n.
func QNR(n *big.Int) *big.Int {
	var w big.Int
	buf := make([]byte, params.BitsIntModN/8)
	for i := 0; i < maxIterations; i++ {
		mustReadBits(buf)
		w.SetBytes(buf)
		w.Mod(&w, n)
		if big.Jacobi(&w, n) == -1 {
			return &w
		}
	}
	panic(ErrMaxIterations)
}

// trialPrimes contains the first 128 odd prime numbers
//
// This amount is chosen to optimize the speed of potentialSafePrime
// for 1024 bits. This is the main size we need.
var trialPrimes = []uint64{
	3, 5, 7, 11, 13, 17, 19, 23,
	29, 31, 37, 41, 43, 47, 53, 59,
	61, 67, 71, 73, 79, 83, 89, 97,
	101, 103, 107, 109, 113, 127, 131, 137,
	139, 149, 151, 157, 163, 167, 173, 179,
	181, 191, 193, 197, 199, 211, 223, 227,
	229, 233, 239, 241, 251, 257, 263, 269,
	271, 277, 281, 283, 293, 307, 311, 313,
	317, 331, 337, 347, 349, 353, 359, 367,
	373, 379, 383, 389, 397, 401, 409, 419,
	421, 431, 433, 439, 443, 449, 457, 461,
	463, 467, 479, 487, 491, 499, 503, 509,
	521, 523, 541, 547, 557, 563, 569, 571,
	577, 587, 593, 599, 601, 607, 613, 617,
	619, 631, 641, 643, 647, 653, 659, 661,
	673, 677, 683, 691, 701, 709, 719, 727,
	733, 739, 743, 751, 757, 761, 769, 773,
}

// potentialSafePrime generates a candidate safe prime, of a certain bit size.
//
// The candidate returned by this function will have undergone a few light
// tests, but not the heavier primality tests like Lucas, or Miller-Rabin.
//
// This function also includes some extra checks to exclude primes that are
// obviously not safe.
func potentialSafePrime(rand io.Reader, bits int) (p *big.Int, err error) {
	// This function was adapted from `rand.Prime`, so you may want to look
	// at how that function is structured.
	//
	// The general strategy is to generate random numbers without an obviously
	// deficient bit pattern, and then check that this number, or one nearby,
	// isn't divisible by any of our trial primes.

	if bits < 2 {
		err = errors.New("math/sample: prime size must be at least 2-bit")
		return
	}

	// The number of significant bits in the last byte of our number
	lastBits := uint(bits % 8)
	if lastBits == 0 {
		lastBits = 8
	}

	// Enough bytes to represent to hold the required bits
	bytes := make([]byte, (bits+7)/8)
	p = new(big.Int)
	scratch := new(big.Int)
	// We store a different remainder for each prime, so that we can then adjust
	// these values with deltas, instead of adjusting our large prime, and
	// then recalculating the remainder.
	mods := make([]uint64, len(trialPrimes))

	for {
		_, err = io.ReadFull(rand, bytes)
		if err != nil {
			return nil, err
		}

		// Clear bits in the first byte to make sure the candidate has a size <= bits.
		bytes[0] &= uint8(int(1<<lastBits) - 1)
		// Don't let the value be too small, i.e, set the most significant two bits.
		//
		// Setting the top two bits, rather than just the top bit,
		// means that when two of these values are multiplied together,
		// the result isn't ever one bit short.
		if lastBits >= 2 {
			bytes[0] |= 0b11 << (lastBits - 2)
		} else {
			// Here lastBits == 1, because lastBits cannot be zero.
			bytes[0] |= 1
			if len(bytes) > 1 {
				bytes[1] |= 0b1000_0000
			}
		}
		// Safe prime are always 3 mod 4, so we set the least significant two bits,
		// and make sure to keep them that way.
		bytes[len(bytes)-1] |= 3

		p.SetBytes(bytes)

		for i := 0; i < len(trialPrimes); i++ {
			scratch.SetUint64(trialPrimes[i])
			mods[i] = scratch.Mod(p, scratch).Uint64()
		}
		// This is a heuristic cap used by OpenSSL.
		maxDelta := (uint64(1) << 32) - trialPrimes[len(trialPrimes)-1]
	NextDelta:
		// We add 4 each iteration, to remain 3 mod 4, which is needed for safe primes.
		for delta := uint64(0); delta < maxDelta; delta += 4 {
			for i := 0; i < len(trialPrimes); i++ {
				remainder := (mods[i] + delta) % trialPrimes[i]
				// If x = 0 mod p, then x is certainly not prime.
				// If x = 1 mod p, then (x - 1) / 2 = 0 mod p, so x cannot be
				// a safe prime either.
				if remainder <= 1 {
					continue NextDelta
				}
			}
			scratch.SetUint64(delta)
			p.Add(p, scratch)

			// There is a tiny possibility that, by adding delta, we caused
			// the number to be one bit too long. Thus we check BitLen
			// here.
			if p.BitLen() == bits {
				return
			}
		}
	}
}

// the number of iterations to use when checking primality
//
// More iterations mean fewer false positives, but more expensive calculations.
//
// 20 is the same number that Go uses internally.
const blumPrimalityIterations = 20

// BlumPrime returns a safe prime p of size params.BitsBlumPrime.
//
// This means that q := (p - 1) / 2 is also a prime number.
//
// This implies that p = 3 mod 4, otherwise q wouldn't be prime.
func BlumPrime() *big.Int {
	// TODO be more flexible on the number of bits in P, Q to avoid square root attack
	one := new(big.Int).SetUint64(1)
	for i := 0; i < 100000; i++ {
		p, err := potentialSafePrime(rand.Reader, params.BitsBlumPrime)
		if err != nil {
			continue
		}
		// For p to be safe, we need q := (p - 1) / 2 to also be prime
		q := new(big.Int).Sub(p, one)
		q.Rsh(q, 1)
		// p is likely to be prime already, so let's first do the other check,
		// which is more likely to fail.
		if !q.ProbablyPrime(blumPrimalityIterations) {
			continue
		}
		// We've only done light checks on p so far, so now we need to make
		// sure that it passes the extensive ones
		if !p.ProbablyPrime(blumPrimalityIterations) {
			continue
		}
		return p
	}
	panic(ErrMaxIterations)
}

// Paillier generate the necessary integers for a Paillier key pair.
// p, q are safe primes ((p - 1) / 2 is also prime), and Blum primes (p = 3 mod 4)
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
