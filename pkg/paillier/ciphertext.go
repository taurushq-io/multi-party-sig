package paillier

import (
	"math/big"
)

type Ciphertext struct {
	c big.Int
}

var one = big.NewInt(1)

// Enc sets the receiver to the encryption of m under the key pk, using the given nonce.
// If nonce is nil then a new one is generated and returned
func (ct *Ciphertext) Enc(pk *PublicKey, m *big.Int, nonce *big.Int) (*Ciphertext, *big.Int) {
	var tmp big.Int
	if nonce == nil {
		nonce = pk.Nonce()
	}

	ct.c.Set(pk.n)                  // N
	ct.c.Add(&ct.c, one)            // N + 1
	ct.c.Exp(&ct.c, m, pk.nSquared) // (N+1)^m mod N^2

	tmp.Exp(nonce, pk.n, pk.nSquared) // rho ^ N mod N^2

	ct.c.Mul(&ct.c, &tmp) // (N+1)^m rho ^ N
	ct.c.Mod(&ct.c, pk.nSquared)

	return ct, nonce
}

func (ct *Ciphertext) Add(pk *PublicKey, ct1, ct2 *Ciphertext) *Ciphertext {
	ct.c.Mul(&ct1.c, &ct2.c)
	ct.c.Mod(&ct.c, pk.nSquared)

	return ct
}

func (ct *Ciphertext) Mul(pk *PublicKey, ctA *Ciphertext, k *big.Int) *Ciphertext {
	ct.c.Exp(&ctA.c, k, pk.nSquared)
	return ct
}

// Equal check whether the receiver is equal to ctA
func (ct *Ciphertext) Equal(ctA *Ciphertext) bool {
	return ct.c.Cmp(&ctA.c) == 0
}

// Randomize multiplies the ciphertext's nonce by a newly generated one.
// ct *= nonce^N for some nonce either given or generated here (if nonce = nil).
// The updated receiver is returned, as well as the nonce update
func (ct *Ciphertext) Randomize(pk *PublicKey, nonce *big.Int) (*Ciphertext, *big.Int) {
	var tmp big.Int
	if nonce == nil {
		nonce = pk.Nonce()
	}
	tmp.Exp(nonce, pk.n, pk.nSquared) // tmp = r^N
	ct.c.Mul(&ct.c, &tmp)             // ct = ct * tmp
	ct.c.Mod(&ct.c, pk.nSquared)      // ct = ct*r^N
	return ct, nonce
}

func (ct *Ciphertext) BigInt() *big.Int {
	return &ct.c
}

func (ct *Ciphertext) Bytes() []byte {
	return ct.c.Bytes()
}
