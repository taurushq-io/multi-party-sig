package paillier

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/sample"
)

type PublicKey struct {
	n, nSquared, nHalf *big.Int
}

func NewPublicKey(n *big.Int) *PublicKey {
	var nSquared, nHalf big.Int
	nSquared.Mul(n, n)
	nHalf.Rsh(n, 1)
	return &PublicKey{
		n:        n,
		nSquared: &nSquared,
		nHalf:    &nHalf,
	}
}

func (pk *PublicKey) Enc(m, nonce *big.Int) (*Ciphertext, *big.Int) {
	var ct Ciphertext
	return ct.Enc(pk, m, nonce)
}

func (pk *PublicKey) Equal(other *PublicKey) bool {
	return pk.n.Cmp(other.n) == 0
}

func (pk *PublicKey) Nonce() *big.Int {
	return sample.Unit(pk.n)
}

func (pk *PublicKey) N() *big.Int {
	return pk.n
}

func (pk *PublicKey) N2() *big.Int {
	return pk.nSquared
}
