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
		phiInv: new(big.Int).ModInverse(phi, pk.n),
		pk:     pk,
	}
}

func (sk *SecretKey) Phi() *big.Int {
	return sk.phi
}

func (sk *SecretKey) PhiInv() *big.Int {
	return sk.phiInv
}

func (sk *SecretKey) PublicKey() *PublicKey {
	return sk.pk
}

func (sk *SecretKey) Dec(c *Ciphertext) *big.Int {
	n := sk.pk.n
	nSquared := sk.pk.nSquared
	phi := sk.Phi()
	phiInv := sk.PhiInv()

	result := new(big.Int)
	result.Exp(&c.c, phi, nSquared)   // r = c^phi 						(mod N^2)
	result.Sub(result, big.NewInt(1)) // r = c^phi - 1
	result.Div(result, n)             // r = [(c^phi - 1)/N]
	result.Mul(result, phiInv)        // r = [(c^phi - 1)/N] • phi^-1
	result.Mod(result, n)             // r = [(c^phi - 1)/N] • phi^-1		(mod N)

	if result.Cmp(sk.pk.nHalf) == 1 {
		result.Sub(result, n)
	}
	return result
}
