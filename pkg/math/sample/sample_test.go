package sample

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
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

func TestPaillier(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	pNat, _ := Paillier(rand.Reader, pl)
	p := pNat.Big()
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

func BenchmarkPaillier(b *testing.B) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	for i := 0; i < b.N; i++ {
		resultNat, _ = Paillier(rand.Reader, pl)
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
