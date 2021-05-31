package sample

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func Rand(bits int) *big.Int {
	b := make([]byte, bits/8)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(b)
}

func TestRand(t *testing.T) {
	Rand(2048)
}

func benchmarkRand(bits int, b *testing.B) {
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		Rand(bits)
	}
}

func BenchmarkRand4096(b *testing.B) { benchmarkRand(4096, b) }
func BenchmarkRand2048(b *testing.B) { benchmarkRand(2048, b) }

func TestStatisticalDistance(t *testing.T) {
	var bound, diff, n big.Int
	bound.SetBit(&bound, 2048, 1)

	for i := 0; i < 10; i++ {
		p, q := Paillier()
		n.Mul(p, q)
		diff.Sub(&bound, &n)
		fmt.Println(2048 - diff.BitLen())
	}
}
