package paillier

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCiphertextValidate(t *testing.T) {
	pk, sk := KeyGen()

	C := big.NewInt(0)
	ct := &Ciphertext{C: C}
	_, err := sk.Dec(ct)
	assert.Error(t, err, "decrypting 0 should fail")

	C.Set(pk.n)
	_, err = sk.Dec(ct)
	assert.Error(t, err, "decrypting N should fail")

	C.Mul(C, big.NewInt(2))
	_, err = sk.Dec(ct)
	assert.Error(t, err, "decrypting 2N should fail")

	C.Set(pk.nSquared)
	_, err = sk.Dec(ct)
	assert.Error(t, err, "decrypting N^2 should fail")
}

func TestCiphertext_Enc(t *testing.T) {
	pk, sk := KeyGen()
	for i := 0; i < 10; i++ {

		b := new(big.Int).SetBit(new(big.Int), 200, 1)
		r1, err := rand.Int(rand.Reader, b)
		require.NoError(t, err)
		r2, err := rand.Int(rand.Reader, b)
		require.NoError(t, err)
		c, err := rand.Int(rand.Reader, b)
		require.NoError(t, err)

		// Test decryption
		ct1, _ := pk.Enc(r1)
		ct2, _ := pk.Enc(r2)

		ct1plus2 := ct1.Clone().Add(pk, ct2)

		r1plus2, err := sk.Dec(ct1plus2)
		assert.NoError(t, err, "should be able to decrypt")

		decCt1, err := sk.Dec(ct1)
		assert.NoError(t, err, "should be able to decrypt")
		require.Equal(t, 0, decCt1.Cmp(r1), "r1= ct1")

		// Test adding
		require.Equal(t, 0, new(big.Int).Add(r1, r2).Cmp(r1plus2))

		ct1times2 := ct1.Clone().Mul(pk, c)

		// Test multiplication
		res := new(big.Int).Mul(c, r1)
		res.Mod(res, pk.n)
		decCt1Times2, err := sk.Dec(ct1times2)
		require.Equal(t, 0, res.Cmp(decCt1Times2))
	}
}
