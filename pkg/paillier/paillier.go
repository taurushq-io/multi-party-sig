package paillier

import (
	"crypto/rand"
	"math/big"
)

var one = big.NewInt(1)

func generateBlumPrime(bits int) *big.Int {
	var p *big.Int
	var err error
	for {
		p, err = rand.Prime(rand.Reader, bits)
		if err != nil {
			continue
		}

		// bit 0 is always 1, so we just need to check that bit 1 is set
		if p.Bit(1) != 1 {
			continue
		}
		return p
	}
}

func KeyGen(secParam int) (pk *PublicKey, sk *SecretKey) {
	var p, q, phi, n, gcd *big.Int
	for {
		p = generateBlumPrime(4 * secParam)
		q = generateBlumPrime(4 * secParam)
		phi = new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))

		n = new(big.Int).Mul(p, q)
		gcd = new(big.Int).GCD(nil, nil, n, phi)

		if gcd.Cmp(one) == 0 {
			break
		}
	}

	pk = NewPublicKey(n)
	sk = NewSecretKey(phi, pk)
	return
}
