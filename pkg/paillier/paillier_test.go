package paillier

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPaillier(t *testing.T) {
	for i := 0; i < 10; i++ {

		pk, sk := KeyGen(256)

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

		ct12 := pk.Add(ct1, ct2)

		r12 := sk.Dec(ct12)

		require.Equal(t, 0, sk.Dec(ct1).Cmp(r1), "r1= ct1")

		// Test adding
		require.Equal(t, 0, new(big.Int).Add(r1, r2).Cmp(r12))

		ct3 := pk.Mult(ct1, c)

		// Test multiplication
		res := new(big.Int).Mul(c, r1)
		res.Mod(res, pk.n)
		require.Equal(t, 0, res.Cmp(sk.Dec(ct3)))

		mult, _ := rand.Int(rand.Reader, b)
		add, _ := rand.Int(rand.Reader, b)

		c2, _ := pk.AffineEnc(ct1, mult, add)
		res2 := sk.Dec(c2)
		cmp2 := new(big.Int).Mul(mult, r1)
		cmp2.Add(add, cmp2)

		require.Equal(t, 0, res2.Cmp(cmp2))

	}
}

func TestPaillierJson(t *testing.T) {
	_, sk := KeyGen(256)
	d, err := json.Marshal(sk)
	require.NoError(t, err)
	skNew := &SecretKey{}
	err = json.Unmarshal(d, skNew)
	require.NoError(t, err)
	println(sk)
}
