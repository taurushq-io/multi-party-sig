package paillier

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/arith"
)

type PublicKey struct {
	n        *big.Int
	nSquared *big.Int
}

func (pk *PublicKey) Enc(m, nonce *big.Int) (*Ciphertext, *big.Int) {
	var ct Ciphertext
	return ct.Enc(pk, m, nonce)
}

//func (pk *PublicKey) AffineEncWithNonce(c *Ciphertext, x, m, nonce *big.Int) *Ciphertext {
//	var result Ciphertext
//	var tmp big.Int
//
//	result.c.Set(pk.n)                        // N
//	result.c.Add(&result.c, one)            // N + 1
//	result.c.Exp(&result.c, m, pk.nSquared) // (N+1)^m mod N^2
//
//	tmp.Exp(nonce, pk.n, pk.nSquared) // rho ^ N mod N^2
//	result.c.Mul(&result.c, &tmp)     // (N+1)^m rho ^ N
//	result.c.Mod(&result.c, pk.nSquared)
//
//	tmp.Exp(&c.c, x, pk.nSquared) // C ^ x
//	result.c.Mul(&result.c, &tmp)   // (N+1)^m rho ^ N
//	result.c.Mod(&result.c, pk.nSquared)
//
//	return &result
//}

//// AffineEnc computes:
////                    Enc(m) + (x • c)
//// and returns the nonce
//func (pk *PublicKey) AffineEnc(c *Ciphertext, x, m *big.Int) (ct *Ciphertext, nonce *big.Int) {
//	nonce = pk.Nonce()
//	ct = pk.AffineEncWithNonce(c, x, m, nonce)
//	return
//}

// Affine computes ctA + x•ctB
func (pk *PublicKey) Affine(ctA, ctB *Ciphertext, x *big.Int) *Ciphertext {
	var result Ciphertext
	result.Mul(pk, ctB, x)
	result.Add(pk, &result, ctA)
	return &result
}

func (pk *PublicKey) Equal(other *PublicKey) bool {
	return pk.n.Cmp(other.n) == 0
}

//func (pk *PublicKey) Add(ct1, ct2 *Ciphertext) *Ciphertext {
//	var result Ciphertext
//	return result.Add(pk, ct1, ct2)
//}

//func (pk *PublicKey) Mult(ct *Ciphertext, k *big.Int) *Ciphertext {
//	var result Ciphertext
//	return result.Mul(pk, ct, k)
//}

func (pk *PublicKey) Nonce() *big.Int {
	return arith.RandomUnit(pk.n)
}

func (pk *PublicKey) N() *big.Int {
	return pk.n
}

func (pk *PublicKey) N2() *big.Int {
	return pk.nSquared
}
