package paillier

import (
	"math/big"
	"math/bits"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

type Ciphertext struct {
	c big.Int
}

const cipherTextWordSize = 4*params.PaillierBits/bits.UintSize + 8

var one = big.NewInt(1)

// Enc sets the receiver to the encryption of m under the key pk, using the given nonce.
// If nonce is nil then a new one is generated and returned
func (ct *Ciphertext) Enc(pk *PublicKey, m *big.Int, nonce *big.Int) (*Ciphertext, *big.Int) {
	tmp := newCipherTextInt()

	if nonce == nil {
		nonce = pk.Nonce()
	}

	tmp.Set(pk.N)                 // N
	tmp.Add(tmp, one)             // N + 1
	ct.c.Exp(tmp, m, pk.NSquared) // (N+1)ᵐ mod N²

	tmp.Exp(nonce, pk.N, pk.NSquared) // rho ^ N mod N²

	ct.c.Mul(&ct.c, tmp) // (N+1)ᵐ rho ^ N
	ct.c.Mod(&ct.c, pk.NSquared)

	return ct, nonce
}

// Add sets ct to the homomorphic sum ct ct₁ ⊕ ct₂.
// ct = ct₁•ct₂ (mod N²)
func (ct *Ciphertext) Add(pk *PublicKey, ct1, ct2 *Ciphertext) *Ciphertext {
	ct.c.Mul(&ct1.c, &ct2.c)
	ct.c.Mod(&ct.c, pk.NSquared)

	return ct
}

// Mul sets ct to the homomorphic multiplication of k ⊙ ctₐ
// ct = ctₐᵏ (mod N²)
func (ct *Ciphertext) Mul(pk *PublicKey, ctA *Ciphertext, k *big.Int) *Ciphertext {
	ct.c.Exp(&ctA.c, k, pk.NSquared)
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
	tmp.Exp(nonce, pk.N, pk.NSquared) // tmp = r^N
	ct.c.Mul(&ct.c, tmp)              // ct = ct * tmp
	ct.c.Mod(&ct.c, pk.NSquared)      // ct = ct*r^N
	return ct, nonce
}

// Int returns a big.Int
func (ct *Ciphertext) Int() *big.Int {
	return &ct.c
}

// Bytes returns the big.Int representation of ct
func (ct *Ciphertext) Bytes() []byte {
	buf := make([]byte, params.BytesCiphertext)
	return ct.c.FillBytes(buf)
}

// SetInt sets ct to a big.Int ciphertext
func (ct *Ciphertext) SetInt(n *big.Int) {
	ct.c.Set(n)
}

func NewCiphertext() *Ciphertext {
	var ct Ciphertext
	buf := make([]big.Word, 0, cipherTextWordSize+2)
	ct.c.SetBits(buf)
	return &ct
}

func newCipherTextInt() *big.Int {
	tmpBuf := make([]big.Word, 0, cipherTextWordSize)
	var tmp big.Int
	tmp.SetBits(tmpBuf)
	return &tmp
}
