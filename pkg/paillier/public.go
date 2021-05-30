package paillier

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

type PublicKey struct {
	N, NSquared, nHalf *big.Int
}

func NewPublicKey(n *big.Int) *PublicKey {
	var nNew, nHalf big.Int
	nNew.Set(n)
	nSquared := newCipherTextInt()
	nSquared.Mul(&nNew, &nNew)
	nHalf.Rsh(&nNew, 1)
	return &PublicKey{
		N:        &nNew,
		NSquared: nSquared,
		nHalf:    &nHalf,
	}
}

// Enc returns the encryption of m under the public key pk.
// If nonce = nil, the a fresh nonce is sampled.
// The nonce used to encrypt is always returned.
//
// ct = (1+N)ᵐρᴺ (mod N²)
func (pk *PublicKey) Enc(m, nonce *big.Int) (*Ciphertext, *big.Int) {
	ct := NewCiphertext()
	return ct.Enc(pk, m, nonce)
}

// Equal returns true if pk = other.
func (pk *PublicKey) Equal(other *PublicKey) bool {
	return pk.N.Cmp(other.N) == 0
}

// Nonce returns a suitable nonce ρ for encryption.
// ρ ∈ ℤₙˣ
func (pk *PublicKey) Nonce() *big.Int {
	return sample.UnitModN(pk.N)
}

func (pk *PublicKey) IsValid() bool {
	// log₂(N) = PaillierBits
	if pk.N.BitLen() != params.PaillierBits {
		return false
	}

	return true
}

func (pk *PublicKey) Clone() *PublicKey {
	var N, NSquared, nHalf big.Int
	return &PublicKey{
		N:        N.Set(pk.N),
		NSquared: NSquared.Set(pk.NSquared),
		nHalf:    nHalf.Set(pk.nHalf),
	}
}
