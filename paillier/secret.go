package paillier

import (
	"math/big"
)

type SecretKey struct {
	PhiInt    *big.Int
	PhiInvInt *big.Int
	PK        *PublicKey
}

func (sk *SecretKey) Phi() *big.Int {
	return sk.PhiInt
}

func (sk *SecretKey) PhiInv() *big.Int {
	return sk.PhiInvInt
}

func (sk *SecretKey) Dec(c *Ciphertext) (m *big.Int) {
	n := sk.PK.n
	nSquared := sk.PK.nSquared
	phi := sk.Phi()
	phiInv := sk.PhiInv()

	result := new(big.Int)
	result.Exp(&c.ct, phi, nSquared)  // r = c^phi 						(mod N^2)
	result.Sub(result, big.NewInt(1)) // r = c^phi - 1
	result.Div(result, n)             // r = [(c^phi - 1)/N]
	result.Mul(result, phiInv)        // r = [(c^phi - 1)/N] • phi^-1
	result.Mod(result, n)             // r = [(c^phi - 1)/N] • phi^-1		(mod N)

	return result
}
