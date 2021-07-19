package paillier

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestCiphertextValidate(t *testing.T) {

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

func TestCiphertext_Enc(t *testing.T) {
	for i := 0; i < 10; i++ {
		b := new(big.Int).SetBit(new(big.Int), 200, 1)
		sample.IntervalL(rand.Reader)
		r1, err := rand.Int(rand.Reader, b)
		require.NoError(t, err)
		r2, err := rand.Int(rand.Reader, b)
		require.NoError(t, err)
		c, err := rand.Int(rand.Reader, b)
		require.NoError(t, err)

		// Test decryption
		ct1, _ := paillierPublic.Enc(r1)
		ct2, _ := paillierPublic.Enc(r2)

		ct1plus2 := ct1.Clone().Add(paillierPublic, ct2)

		r1plus2, err := paillierSecret.Dec(ct1plus2)
		assert.NoError(t, err, "should be able to decrypt")

		decCt1, err := paillierSecret.Dec(ct1)
		assert.NoError(t, err, "should be able to decrypt")
		require.Equal(t, 0, decCt1.Cmp(r1), "r1= ct1")

		// Test adding
		require.Equal(t, 0, new(big.Int).Add(r1, r2).Cmp(r1plus2))

		ct1times2 := ct1.Clone().Mul(paillierPublic, c)

		// Test multiplication
		res := new(big.Int).Mul(c, r1)
		res.Mod(res, paillierPublic.n)
		decCt1Times2, err := paillierSecret.Dec(ct1times2)
		require.Equal(t, 0, res.Cmp(decCt1Times2))
	}
}
