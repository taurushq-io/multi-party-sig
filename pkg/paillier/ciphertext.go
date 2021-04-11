package paillier

import (
	"math/big"
	"math/bits"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

type Ciphertext struct {
	c big.Int
}

const cipherTextWordSize = params.PaillierBits/bits.UintSize + 1

var one = big.NewInt(1)

// Enc sets the receiver to the encryption of m under the key pk, using the given nonce.
// If nonce is nil then a new one is generated and returned
func (ct *Ciphertext) Enc(pk *PublicKey, m *big.Int, nonce *big.Int) (*Ciphertext, *big.Int) {
	tmp := newCipherTextInt()

	if nonce == nil {
		nonce = pk.Nonce()
	}

	ct.c.Set(pk.n)                  // N
	ct.c.Add(&ct.c, one)            // N + 1
	ct.c.Exp(&ct.c, m, pk.nSquared) // (N+1)ᵐ mod N²

	tmp.Exp(nonce, pk.n, pk.nSquared) // rho ^ N mod N²

	ct.c.Mul(&ct.c, &tmp) // (N+1)ᵐ rho ^ N
	ct.c.Mod(&ct.c, pk.nSquared)

	return ct, nonce
}

// Add sets ct to the homomorphic sum ct ct₁ ⊕ ct₂.
// ct = ct₁•ct₂ (mod N²)
func (ct *Ciphertext) Add(pk *PublicKey, ct1, ct2 *Ciphertext) *Ciphertext {
	ct.c.Mul(&ct1.c, &ct2.c)
	ct.c.Mod(&ct.c, pk.nSquared)

	return ct
}

// Mul sets ct to the homomorphic multiplication of k ⊙ ctₐ
// ct = ctₐᵏ (mod N²)
func (ct *Ciphertext) Mul(pk *PublicKey, ctA *Ciphertext, k *big.Int) *Ciphertext {
	ct.c.Exp(&ctA.c, k, pk.nSquared)
	return ct
}

// Equal check whether ct ≡ ctₐ (mod N²)
func (ct *Ciphertext) Equal(ctA *Ciphertext) bool {
	return ct.c.Cmp(&ctA.c) == 0
}

// Randomize multiplies the ciphertext's nonce by a newly generated one.
// ct *= nonceᴺ for some nonce either given or generated here (if nonce = nil).
// The updated receiver is returned, as well as the nonce update
func (ct *Ciphertext) Randomize(pk *PublicKey, nonce *big.Int) (*Ciphertext, *big.Int) {
	tmp := newCipherTextInt()
	if nonce == nil {
		nonce = pk.Nonce()
	}
	tmp.Exp(nonce, pk.n, pk.nSquared) // tmp = r^N
	ct.c.Mul(&ct.c, &tmp)             // ct = ct * tmp
	ct.c.Mod(&ct.c, pk.nSquared)      // ct = ct*r^N
	return ct, nonce
}

//Not sure we need this now
func (ct *Ciphertext) Int() *big.Int {
	return &ct.c
}

// Bytes returns the big.Int representation of ct
func (ct *Ciphertext) Bytes() []byte {
	return ct.c.Bytes()
}

// SetInt sets ct to a big.Int ciphertext
func (ct *Ciphertext) SetInt(n *big.Int) {
	ct.c.Set(n)
}

func newCipherTextInt() big.Int {
	tmpBuf := make([]big.Word, 0, cipherTextWordSize)
	var tmp big.Int
	tmp.SetBits(tmpBuf)
	return tmp
}
