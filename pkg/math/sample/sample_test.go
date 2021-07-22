package sample

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

func TestModN(t *testing.T) {
	n := safenum.ModulusFromUint64(3 * 11 * 65519)
	x := ModN(rand.Reader, n)
	_, _, lt := x.CmpMod(n)
	if lt != 1 {
		t.Errorf("ModN generated a number >= %v: %v", x, n)
	}
}

const blumPrimeProbabilityIterations = 20

func TestBlumPrime(t *testing.T) {
	p := BlumPrime(rand.Reader).Big()
	if !p.ProbablyPrime(blumPrimeProbabilityIterations) {
		t.Error("BlumPrime generated a non prime number: ", p)
	}
	q := new(big.Int).Sub(p, new(big.Int).SetUint64(1))
	q.Rsh(q, 1)
	if !q.ProbablyPrime(blumPrimeProbabilityIterations) {
		t.Error("p isn't safe because (p - 1) / 2 isn't prime", q)
	}
}

// This exists to save the results of functions we want to benchmark, to avoid
// having them optimized away.
var resultNat *safenum.Nat

func BenchmarkBlumPrime(b *testing.B) {
	for i := 0; i < b.N; i++ {
		resultNat = BlumPrime(rand.Reader)
	}
}

func BenchmarkModN(b *testing.B) {
	b.StopTimer()
	nBytes := make([]byte, (params.BitsPaillier+7)/8)
	_, _ = rand.Read(nBytes)
	n := safenum.ModulusFromBytes(nBytes)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultNat = ModN(rand.Reader, n)
	}
}
