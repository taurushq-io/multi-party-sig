package paillier

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
)

type PublicKey struct {
	n, nSquared, nHalf *big.Int
}

func NewPublicKey(n *big.Int) *PublicKey {
	var nNew, nHalf big.Int
	nNew.Set(n)
	nSquared := newCipherTextInt()
	nSquared.Mul(&nNew, &nNew)
	nHalf.Rsh(&nNew, 1)
	return &PublicKey{
		n:        &nNew,
		nSquared: &nSquared,
		nHalf:    &nHalf,
	}
}

// Enc returns the encryption of m under the public key pk.
// If nonce = nil, the a fresh nonce is sampled.
// The nonce used to encrypt is always returned.
//
// ct = (1+N)ᵐρᴺ (mod N²)
func (pk *PublicKey) Enc(m, nonce *big.Int) (*Ciphertext, *big.Int) {
	var ct Ciphertext
	return ct.Enc(pk, m, nonce)
}

// Equal returns true if pk = other.
func (pk *PublicKey) Equal(other *PublicKey) bool {
	return pk.n.Cmp(other.n) == 0
}

// Nonce returns a suitable nonce ρ for encryption.
// ρ ∈ ℤₙˣ
func (pk *PublicKey) Nonce() *big.Int {
	return sample.UnitModN(pk.n)
}

// N returns the big.Int N of the public key.
// For efficiency, the value returned is a pointer to the same underlying N.
// WARNING: Do not modify the returned value.
func (pk *PublicKey) N() *big.Int {
	return pk.n
}

// N2 returns the big.Int N² of the public key.
// For efficiency, the value returned is a pointer to the same underlying N².
// WARNING: Do not modify the returned value.
func (pk *PublicKey) N2() *big.Int {
	return pk.nSquared
}
