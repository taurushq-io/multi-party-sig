package sample

import (
	"math/big"
	"testing"
)

const blumPrimeProbabilityIterations = 20

func TestBlumPrime(t *testing.T) {
	p := BlumPrime()
	if !p.ProbablyPrime(blumPrimeProbabilityIterations) {
		t.Error("BlumPrime generated a non prime number: ", p)
	}
}

// This exists to save the results of functions we want to benchmark, to avoid
// having them optimized away.
var resultBig *big.Int

func BenchmarkBlumPrime(b *testing.B) {
	for i := 0; i < b.N; i++ {
		resultBig = BlumPrime()
	}
}
