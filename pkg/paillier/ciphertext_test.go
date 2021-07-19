package paillier

import (
	"crypto/rand"
	"math/big"
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/assert"
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
}

func reinit() {
	paillierPublic, paillierSecret = KeyGen()
}

func TestCiphertextValidate(t *testing.T) {
	if !testing.Short() {
		reinit()
	}

	C := big.NewInt(0)
	ct := &Ciphertext{C: C}
	_, err := paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting 0 should fail")

	C.Set(paillierPublic.n)
	_, err = paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting N should fail")

	C.Mul(C, big.NewInt(2))
	_, err = paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting 2N should fail")

	C.Set(paillierPublic.nSquared)
	_, err = paillierSecret.Dec(ct)
	assert.Error(t, err, "decrypting N^2 should fail")
}

func testEncDecRoundTrip(x int64) bool {
	m := new(big.Int).SetInt64(x)
	ciphertext, _ := paillierPublic.Enc(m)
	shouldBeM, err := paillierSecret.Dec(ciphertext)
	if err != nil {
		return false
	}
	return m.Cmp(shouldBeM) == 0
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

func testEncDecHomomorphic(a int64, b int64) bool {
	ma := new(big.Int).SetInt64(a)
	mb := new(big.Int).SetInt64(b)
	ca, _ := paillierPublic.Enc(ma)
	cb, _ := paillierPublic.Enc(mb)
	expected := new(big.Int).Add(ma, mb)
	actual, err := paillierSecret.Dec(ca.Add(paillierPublic, cb))
	if err != nil {
		return false
	}
	return actual.Cmp(expected) == 0
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

func testEncDecScalingHomomorphic(s int64, x int64) bool {
	m := new(big.Int).SetInt64(x)
	sBig := new(big.Int).SetInt64(s)
	c, _ := paillierPublic.Enc(m)
	expected := new(big.Int).Mul(m, sBig)
	actual, err := paillierSecret.Dec(c.Mul(paillierPublic, sBig))
	if err != nil {
		return false
	}
	return actual.Cmp(expected) == 0
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
	m := sample.IntervalLEps(rand.Reader)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultCiphertext, _ = paillierPublic.Enc(m)
	}
}

func BenchmarkAddCiphertext(b *testing.B) {
	b.StopTimer()
	m := sample.IntervalLEps(rand.Reader)
	c, _ := paillierPublic.Enc(m)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultCiphertext = c.Add(paillierPublic, c)
	}
}

func BenchmarkMulCiphertext(b *testing.B) {
	b.StopTimer()
	m := sample.IntervalLEps(rand.Reader)
	c, _ := paillierPublic.Enc(m)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		resultCiphertext = c.Mul(paillierPublic, m)
	}
}
