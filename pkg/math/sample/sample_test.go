package sample

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestSample(t *testing.T) {
	//_, _, n, _ := Paillier()
	//pk := paillier.NewPublicKey(n)
	//for i := 0; i < 1024; i++ {
	//	m, _ := rand.Int(rand.Reader, n)
	//	c, nonce := pk.Enc(m, nil)
	//	fmt.Println(c.Int().BitLen(), nonce.BitLen())
	//}
}

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
	var bound, diff big.Int
	bound.SetBit(&bound, 2048, 1)

	for i := 0; i < 10; i++ {
		_, _, n, _ := Paillier()
		diff.Sub(&bound, n)
		fmt.Println(2048 - diff.BitLen())
	}
}
