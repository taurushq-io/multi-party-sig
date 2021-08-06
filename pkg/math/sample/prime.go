package sample

import (
	"io"
	"math"
	"math/big"
	"sync"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

func primes(below uint32) []uint32 {
	sieve := make([]bool, below)

	for i := 2; i < len(sieve); i++ {
		sieve[i] = true
	}

	for p := 2; p*p < len(sieve); p++ {
		if !sieve[p] {
			continue
		}
		for i := p << 1; i < len(sieve); i += p {
			sieve[i] = false
		}
	}

	nF := float64(below)
	out := make([]uint32, 0, int(nF/math.Log(nF)))
	for p := uint32(3); p < below; p++ {
		if sieve[p] {
			out = append(out, p)
		}
	}

	return out
}

const sieveSize = 1 << 18
const primeBound = 1 << 20

// the number of iterations to use when checking primality
//
// More iterations mean fewer false positives, but more expensive calculations.
//
// 20 is the same number that Go uses internally.
const blumPrimalityIterations = 20

var thePrimes []uint32
var initPrimes sync.Once

func tryBlumPrime(rand io.Reader) *safenum.Nat {
	initPrimes.Do(func() {
		thePrimes = primes(primeBound)
	})

	bytes := make([]byte, (params.BitsBlumPrime+7)/8)

	_, err := io.ReadFull(rand, bytes)
	if err != nil {
		return nil
	}
	// Clear low bits to ensure that our number is 3 mod 4
	bytes[len(bytes)-1] |= 3
	// Ensure that the top two bits are set
	bytes[0] |= 0xC0

	base := new(big.Int).SetBytes(bytes)

	// sieve checks the candidacy of base, base+1, base+2, etc.
	sieve := make([]bool, sieveSize)
	for i := 0; i < len(sieve); i++ {
		sieve[i] = true
	}
	// Remove candidates that aren't 3 mod 4
	for i := 1; i+2 < len(sieve); i += 4 {
		sieve[i] = false
		sieve[i+1] = false
		sieve[i+2] = false
	}
	// sieve out primes
	remainder := new(big.Int)
	for _, prime := range thePrimes {
		remainder.SetUint64(uint64(prime))
		remainder.Mod(base, remainder)

		r := int(remainder.Uint64())
		primeInt := int(prime)
		firstMultiple := primeInt - r
		if r == 0 {
			firstMultiple = 0
		}
		for i := firstMultiple; i+1 < len(sieve); i += primeInt {
			sieve[i] = false
			sieve[i+1] = false
		}
	}
	p := new(big.Int)
	q := new(big.Int)
	for delta := 0; delta < len(sieve); delta++ {
		if !sieve[delta] {
			continue
		}

		p.SetUint64(uint64(delta))
		p.Add(p, base)
		if p.BitLen() > params.BitsBlumPrime {
			return nil
		}
		q.Rsh(p, 1)
		// p is likely to be prime already, so let's first do the other check,
		// which is more likely to fail.
		if !q.ProbablyPrime(blumPrimalityIterations) {
			continue
		}
		if !p.ProbablyPrime(0) {
			continue
		}
		return new(safenum.Nat).SetBig(p, params.BitsBlumPrime)
	}

	return nil
}

// Paillier generate the necessary integers for a Paillier key pair.
// p, q are safe primes ((p - 1) / 2 is also prime), and Blum primes (p = 3 mod 4)
// n = pq.
func Paillier(rand io.Reader, pl *pool.Pool) (p, q *safenum.Nat) {
	reader := pool.NewLockedReader(rand)
	results := pl.Search(2, func() interface{} {
		q := tryBlumPrime(reader)
		// You have to do this, because of how Go handles nil.
		if q == nil {
			return nil
		}
		return q
	})
	p, q = results[0].(*safenum.Nat), results[1].(*safenum.Nat)
	return
}
