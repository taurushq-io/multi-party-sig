package paillier

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type PublicKey struct {
	n        *big.Int
	nSquared *big.Int
}

func (pk *PublicKey) Enc(m *big.Int) (ct *Ciphertext, nonce *Nonce) {
	nonce = pk.Nonce()
	ct = pk.EncWithNonce(m, nonce.BigInt())

	return
}

func (pk *PublicKey) EncWithNonce(m *big.Int, nonce *big.Int) (ct *Ciphertext) {
	N := pk.N()
	NSquared := pk.N2()

	ct = &Ciphertext{big.Int{}}
	res := &ct.ct

	res.Set(N)                // N
	res.Add(res, one)         // N + 1
	res.Exp(res, m, NSquared) // (N+1)^m mod N^2

	tmp := new(big.Int)
	tmp.Exp(nonce, N, NSquared) // rho ^ N mod N^2

	res.Mul(res, tmp) // (N+1)^m rho ^ N
	res.Mod(res, NSquared)

	return
}

func (pk *PublicKey) AffineWithNonce(c *Ciphertext, x, m, nonce *big.Int) (ct *Ciphertext) {
	N := pk.N()
	NSquared := pk.N2()
	tmp := new(big.Int)

	ct = &Ciphertext{big.Int{}}
	res := &ct.ct

	res.Set(N)                // N
	res.Add(res, one)         // N + 1
	res.Exp(res, m, NSquared) // (N+1)^m mod N^2

	tmp.Exp(nonce, N, NSquared) // rho ^ N mod N^2
	res.Mul(res, tmp)           // (N+1)^m rho ^ N
	res.Mod(res, NSquared)

	tmp.Exp(c.BigInt(), x, NSquared) // C ^ x
	res.Mul(res, tmp)                // (N+1)^m rho ^ N
	res.Mod(res, NSquared)

	return
}

func (pk *PublicKey) Affine(c *Ciphertext, x, m *big.Int) (ct *Ciphertext, nonce *Nonce) {
	nonce = pk.Nonce()
	ct = pk.AffineWithNonce(c, x, m, nonce.BigInt())
	return
}

func (pk *PublicKey) Equal(other *PublicKey) bool {
	return pk.n.Cmp(other.n) == 0
}

func (pk *PublicKey) Add(ct1, ct2 *Ciphertext) (ct *Ciphertext) {
	ct = &Ciphertext{big.Int{}}
	res := &ct.ct
	res.Mul(&ct1.ct, &ct2.ct)
	res.Mod(res, pk.nSquared)
	return
}

func (pk *PublicKey) Mult(k *big.Int, ct1 *Ciphertext) (ct *Ciphertext) {
	ct = &Ciphertext{big.Int{}}
	res := &ct.ct
	res.Exp(&ct1.ct, k, pk.nSquared)
	return
}

func (pk *PublicKey) Nonce() (nonce *Nonce) {
	gcd := new(big.Int)
	tmp := new(big.Int)
	N := pk.N()
	for i := 0; i < 100; i++ {
		tmp, _ = rand.Int(rand.Reader, N)
		gcd.GCD(nil, nil, N, tmp)
		if gcd.Cmp(one) == 0 {
			nonce = &Nonce{*tmp}
			return
		}
	}
	return
}

func (pk *PublicKey) N() *big.Int {
	return pk.n
}

func (pk *PublicKey) N2() *big.Int {
	return pk.nSquared
}

func (pk PublicKey) MarshalJSON() ([]byte, error) {
	return []byte(pk.n.String()), nil
}

func (pk *PublicKey) UnmarshalJSON(p []byte) error {
	if string(p) == "null" {
		return nil
	}
	var z big.Int
	_, ok := z.SetString(string(p), 10)
	if !ok {
		return fmt.Errorf("not a valid big integer: %s", p)
	}
	pk.n = &z
	pk.nSquared = new(big.Int).Mul(pk.n, pk.n)
	return nil
}
