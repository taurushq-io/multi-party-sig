package paillier

import (
	"crypto/rand"
	"math/big"
	"testing"
	"testing/quick"

	"github.com/cronokirby/safenum"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/cmp-ecdsa/internal/proto"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
)

var (
	paillierPublic *PublicKey
	paillierSecret *SecretKey
)

func init() {
	var p, q big.Int
	p.SetString("178057883835183286117512200677440244390145099259082383308945719698013763573399954450532998268905835885924159614319313406003087379446561971296106546809183979483713400989852915992871444851374827190424830370732455638126086633695206754034038375138787276649530329444888582356387252561437032663445969018257131309467", 10)
	q.SetString("154015006160854235002007557023803468376448277365405705676551314882683128790125170467276370601034321782779924625687921529410458399255587689405771572795902602356870537998583671038752961901536910952455193645347654842352350434852963582643875873134652544209964216130513008483123534718118886460747385334474444035767", 10)
	paillierSecret = NewSecretKeyFromPrimes(&p, &q)
	paillierPublic = paillierSecret.PublicKey
	if err := paillierSecret.Validate(); err != nil {
		panic(err)
	}
}

func reinit() {
	paillierPublic, paillierSecret = KeyGen()
}

func TestCiphertextValidate(t *testing.T) {
	if !testing.Short() {
		reinit()
	}

	C := new(safenum.Nat)
	ct := &Ciphertext{&proto.NatMarshaller{Nat: C}}
	_, err := paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting 0 should fail")

	C.SetNat(paillierPublic.nNat)
	_, err = paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting N should fail")

	C.Add(C, C, -1)
	_, err = paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting 2N should fail")

	C.SetNat(paillierPublic.nSquared.Nat())
	_, err = paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting N^2 should fail")
}

func testEncDecRoundTrip(x uint64, xNeg bool) bool {
	m := new(safenum.Int).SetUint64(x)
	if xNeg {
		m.Neg(1)
	}
	ciphertext, _ := paillierPublic.Enc(m)
	shouldBeM, err := paillierSecret.Dec(ciphertext)
	if err != nil {
		return false
	}
	return m.Eq(shouldBeM) == 1
}

func TestEncDecRoundTrip(t *testing.T) {
	if !testing.Short() {
		reinit()
	}
	err := quick.Check(testEncDecRoundTrip, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

func testEncDecHomomorphic(a, b uint64, aNeg, bNeg bool) bool {
	ma := new(safenum.Int).SetUint64(a)
	if aNeg {
		ma.Neg(1)
	}
	mb := new(safenum.Int).SetUint64(b)
	if bNeg {
		mb.Neg(1)
	}
	ca, _ := paillierPublic.Enc(ma)
	cb, _ := paillierPublic.Enc(mb)
	expected := new(safenum.Int).Add(ma, mb, -1)
	actual, err := paillierSecret.Dec(ca.Add(paillierPublic, cb))
	if err != nil {
		return false
	}
	return actual.Eq(expected) == 1
}

func TestEncDecHomomorphic(t *testing.T) {
	if !testing.Short() {
		reinit()
	}
	err := quick.Check(testEncDecHomomorphic, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

func testEncDecScalingHomomorphic(s, x uint64, sNeg, xNeg bool) bool {
	m := new(safenum.Int).SetUint64(x)
	if xNeg {
		m.Neg(1)
	}
	sInt := new(safenum.Int).SetUint64(s)
	if sNeg {
		sInt.Neg(1)
	}
	c, _ := paillierPublic.Enc(m)
	expected := new(safenum.Int).Mul(m, sInt, -1)
	actual, err := paillierSecret.Dec(c.Mul(paillierPublic, sInt))
	if err != nil {
		return false
	}
	return actual.Eq(expected) == 1
}

func TestEncDecScalingHomomorphic(t *testing.T) {
	if !testing.Short() {
		reinit()
	}
	err := quick.Check(testEncDecScalingHomomorphic, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

// Used to avoid benchmark optimization
var resultCiphertext *Ciphertext

func BenchmarkEncryption(b *testing.B) {
	b.StopTimer()
	m := sample.IntervalLEpsSecret(rand.Reader)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultCiphertext, _ = paillierPublic.Enc(m)
	}
}

func BenchmarkAddCiphertext(b *testing.B) {
	b.StopTimer()
	m := sample.IntervalLEpsSecret(rand.Reader)
	c, _ := paillierPublic.Enc(m)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultCiphertext = c.Add(paillierPublic, c)
	}
}

func BenchmarkMulCiphertext(b *testing.B) {
	b.StopTimer()
	m := sample.IntervalLEpsSecret(rand.Reader)
	c, _ := paillierPublic.Enc(m)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultCiphertext = c.Mul(paillierPublic, m)
	}
}
