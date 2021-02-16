package paillier

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type (
	Ciphertext struct {
		ct big.Int
	}
	Nonce struct {
		n big.Int
	}
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
	phiInv := new(big.Int).ModInverse(phi, n)

	pk = &PublicKey{n: n, nSquared: new(big.Int).Mul(n, n)}
	sk = &SecretKey{
		PhiInt:    phi,
		PhiInvInt: phiInv,
		PK:        pk,
	}
	return
}

func (n *Nonce) BigInt() *big.Int {
	return &(n.n)
}

func (ct *Ciphertext) BigInt() *big.Int {
	return &(ct.ct)
}

func (ct Ciphertext) MarshalJSON() ([]byte, error) {
	return []byte(ct.ct.String()), nil
}

func (ct *Ciphertext) UnmarshalJSON(p []byte) error {
	if string(p) == "null" {
		return nil
	}
	var z big.Int
	_, ok := z.SetString(string(p), 10)
	if !ok {
		return fmt.Errorf("not a valid big integer: %s", p)
	}
	ct.ct = z
	return nil
}

func (n Nonce) MarshalJSON() ([]byte, error) {
	return []byte(n.n.String()), nil
}

func (n *Nonce) UnmarshalJSON(p []byte) error {
	if string(p) == "null" {
		return nil
	}
	var z big.Int
	_, ok := z.SetString(string(p), 10)
	if !ok {
		return fmt.Errorf("not a valid big integer: %s", p)
	}
	n.n = z
	return nil
}
