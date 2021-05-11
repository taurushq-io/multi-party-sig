package paillier

import (
	"math/big"
)

type SecretKey struct {
	phi, phiInv *big.Int
	pk          *PublicKey
}

func NewSecretKey(phi *big.Int, pk *PublicKey) *SecretKey {
	return &SecretKey{
		phi:    phi,
		phiInv: new(big.Int).ModInverse(phi, pk.N),
		pk:     pk,
	}
}

// Phi returns ϕ = (p-1)(q-1).
// For efficiency, the value returned is a pointer to the same underlying ϕ.
// WARNING: Do not modify the returned value.
func (sk *SecretKey) Phi() *big.Int {
	return sk.phi
}

// PhiInv returns ϕ⁻¹ mod N.
// For efficiency, the value returned is a pointer to the same underlying ϕ⁻¹.
// WARNING: Do not modify the returned value.
func (sk *SecretKey) PhiInv() *big.Int {
	return sk.phiInv
}

// PublicKey returns the associated PublicKey
func (sk *SecretKey) PublicKey() *PublicKey {
	return sk.pk
}

// Dec decrypts c and returns the plaintext m ∈ ± (N-2)/2
func (sk *SecretKey) Dec(c *Ciphertext) *big.Int {
	n := sk.pk.N
	nSquared := sk.pk.NSquared
	phi := sk.Phi()
	phiInv := sk.PhiInv()

	result := new(big.Int)
	result.Exp(&c.c, phi, nSquared)   // r = c^phi 						(mod N²)
	result.Sub(result, big.NewInt(1)) // r = c^phi - 1
	result.Div(result, n)             // r = [(c^phi - 1)/N]
	result.Mul(result, phiInv)        // r = [(c^phi - 1)/N] • phi^-1
	result.Mod(result, n)             // r = [(c^phi - 1)/N] • phi^-1		(mod N)

	if result.Cmp(sk.pk.nHalf) == 1 {
		result.Sub(result, n)
	}
	return result
}
