package paillier

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
)

func TestPaillier(t *testing.T) {
	for i := 0; i < 10; i++ {
		pk, sk := KeyGen()

		b := new(big.Int).SetBit(new(big.Int), 200, 1)
		r1, err := rand.Int(rand.Reader, b)
		require.NoError(t, err)
		r2, err := rand.Int(rand.Reader, b)
		require.NoError(t, err)
		c, err := rand.Int(rand.Reader, b)
		require.NoError(t, err)

		// Test decryption
		ct1, _ := pk.Enc(r1, nil)
		ct2, _ := pk.Enc(r2, nil)

		var ct1plus2, ct1times2 Ciphertext
		ct1plus2.Add(pk, ct1, ct2)

		r1plus2 := sk.Dec(&ct1plus2)

		require.Equal(t, 0, sk.Dec(ct1).Cmp(r1), "r1= ct1")

		// Test adding
		require.Equal(t, 0, new(big.Int).Add(r1, r2).Cmp(r1plus2))

		ct1times2.Mul(pk, ct1, c)

		// Test multiplication
		res := new(big.Int).Mul(c, r1)
		res.Mod(res, pk.n)
		require.Equal(t, 0, res.Cmp(sk.Dec(&ct1times2)))
	}
}

func TestPaillierJson(t *testing.T) {
	_, sk := KeyGen()
	d, err := json.Marshal(sk)
	require.NoError(t, err)
	skNew := &SecretKey{}
	err = json.Unmarshal(d, skNew)
	require.NoError(t, err)
	println(sk)
}
func TestSample(t *testing.T) {
	_, _, n, _ := sample.Paillier()
	pk := NewPublicKey(n)
	for i := 0; i < 10; i++ {
		m, _ := rand.Int(rand.Reader, n)
		c, nonce := pk.Enc(m, nil)
		fmt.Println(4096-c.Int().BitLen(), 2048-nonce.BitLen())
	}
}
