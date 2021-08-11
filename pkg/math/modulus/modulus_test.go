package modulus

import (
	"crypto/rand"
	mrand "math/rand"
	"testing"

	"github.com/cronokirby/safenum"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

func TestModulus_Exp(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	m := FromFactors(p, q, 2, 2)
	// p²
	pSquared := new(safenum.Nat).Mul(p, p, -1)
	// q²
	qSquared := new(safenum.Nat).Mul(q, q, -1)
	// n = p² q²
	nExpected := new(safenum.Nat).Mul(pSquared, qSquared, -1)
	assert.True(t, nExpected.Eq(m.n.Nat()) == 1, "computed n is not equal to p² q²")
	n := safenum.ModulusFromNat(nExpected)
	x := sample.ModN(rand.Reader, n)
	e := sample.IntervalLN(rand.Reader).Abs()

	xeExpected := new(safenum.Nat).Exp(x, e, n)
	xeActual := m.Exp(x, e)
	assert.True(t, xeExpected.Eq(xeActual) == 1, "computed n is not equal to p² q²")
}

func benchmarkExpCRT(b *testing.B, m *Modulus, size int) {
	r := mrand.New(mrand.NewSource(0))
	x := new(safenum.Nat)
	e := new(safenum.Nat)
	buf := make([]byte, size)
	for i := 0; i < b.N; i++ {
		x = sample.ModN(r, n)
		r.Read(buf)
		e.SetBytes(buf)
		m.Exp(x, e)
	}
}
func benchmarkExpICRT(b *testing.B, m *Modulus, size int) {
	r := mrand.New(mrand.NewSource(0))
	x := new(safenum.Nat)
	e := new(safenum.Int)
	buf := make([]byte, size)
	for i := 0; i < b.N; i++ {
		x = sample.ModN(r, n)
		r.Read(buf)
		e.SetBytes(buf)
		e.Neg(safenum.Choice(r.Uint32() & 1))
		m.ExpI(x, e)
	}
}

func BenchmarkExp(b *testing.B) {
	sizes := map[string]int{
		"256":  256,
		"512":  512,
		"1024": 1024,
		"4096": 4096,
	}
	ms := map[string]*Modulus{
		"fast": mFast,
		"slow": mSlow,
	}
	for sizeStr, size := range sizes {
		for mStr, m := range ms {
			b.Run(sizeStr+mStr+"Nat", func(b *testing.B) {
				benchmarkExpCRT(b, m, size)
			})
			b.Run(sizeStr+mStr+"Int", func(b *testing.B) {
				benchmarkExpICRT(b, m, size)
			})
		}
	}
}

var (
	p, q         *safenum.Nat
	n            *safenum.Modulus
	mFast, mSlow *Modulus
)

func init() {
	p, _ = new(safenum.Nat).SetHex("D08769E92F80F7FDFB85EC02AFFDAED0FDE2782070757F191DCDC4D108110AC1E31C07FC253B5F7B91C5D9F203AA0572D3F2062A3D2904C535C6ACCA7D5674E1C2640720E762C72B66931F483C2D910908CF02EA6723A0CBBB1016CA696C38FEAC59B31E40584C8141889A11F7A38F5B17811D11F42CD15B8470F11C6183802B")
	q, _ = new(safenum.Nat).SetHex("C21239C3484FC3C8409F40A9A22FABFFE26CA10C27506E3E017C2EC8C4B98D7A6D30DED0686869884BE9BAD27F5241B7313F73D19E9E4B384FABF9554B5BB4D517CBAC0268420C63D545612C9ADABEEDF20F94244E7F8F2080B0C675AC98D97C580D43375F999B1AC127EC580B89B2D302EF33DD5FD8474A241B0398F6088CA7")
	nNat := new(safenum.Nat).Mul(p, q, -1)
	nNat.Mul(nNat, nNat, -1)
	n = safenum.ModulusFromNat(nNat)
	mFast = FromFactors(p, q, 2, 2)
	mSlow = FromN(n)
}
