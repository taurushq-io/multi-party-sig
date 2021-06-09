package paillier

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

var (
	ErrNotBlum         = errors.New("prime factor is not equivalent to 3 (mod 4)")
	ErrPrimeBadLength  = errors.New("prime factor is not the right length")
	ErrWrongPhi        = errors.New("paillier.SecretKey: ϕ ≠ (p-1)*(q-1)")
	ErrWrongPhiInv     = errors.New("paillier.SecretKey: ϕ*ϕ⁻¹ mod N ≠ 1")
	ErrModulusMismatch = errors.New("paillier.SecretKey: public key has different N")
	ErrNotPrime        = errors.New("supposed prime factor is not prime")
)

type SecretKey struct {
	// P, Q such that N = P⋅Q
	P, Q *big.Int
	// Phi = ϕ = (P-1)(Q-1)
	Phi *big.Int
	// PhiInv = ϕ⁻¹ mod N
	PhiInv *big.Int
	pk     PublicKey
}

func KeyGen() (pk *PublicKey, sk *SecretKey) {
	sk = NewSecretKey()
	pk = sk.PublicKey()
	return
}

func NewSecretKey() *SecretKey {
	return NewSecretKeyFromPrimes(sample.Paillier())
}

func NewSecretKeyFromPrimes(P, Q *big.Int) *SecretKey {
	var n, p, q, phi, phiInv big.Int
	one := big.NewInt(1)

	n.Mul(P, Q)
	pk := NewPublicKey(&n)

	p.Sub(P, one)   // P-1
	q.Sub(Q, one)   // Q-1
	phi.Mul(&p, &q) // ϕ = (P-1)(Q-1)

	phiInv.ModInverse(&phi, &n) // ϕ⁻¹ mod N

	p.Set(P)
	q.Set(Q)

	return &SecretKey{
		P:      p.Set(P),
		Q:      q.Set(Q),
		Phi:    &phi,
		PhiInv: &phiInv,
		pk:     *pk,
	}
}

// PublicKey returns the associated PublicKey
func (sk *SecretKey) PublicKey() *PublicKey {
	return &sk.pk
}

// Dec decrypts c and returns the plaintext m ∈ ± (N-2)/2
func (sk *SecretKey) Dec(c *Ciphertext) *big.Int {
	n := sk.pk.N
	nSquared := sk.pk.nSquared
	phi := sk.Phi
	phiInv := sk.PhiInv

	result := new(big.Int)
	result.Exp(&c.c, phi, nSquared)   // r = c^Phi 						(mod N²)
	result.Sub(result, big.NewInt(1)) // r = c^Phi - 1
	result.Div(result, n)             // r = [(c^Phi - 1)/N]
	result.Mul(result, phiInv)        // r = [(c^Phi - 1)/N] • Phi^-1
	result.Mod(result, n)             // r = [(c^Phi - 1)/N] • Phi^-1		(mod N)

	if result.Cmp(sk.pk.nHalf) == 1 {
		result.Sub(result, n)
	}
	return result
}

func (sk *SecretKey) Clone() *SecretKey {
	var p, q, phi, phiInv big.Int
	return &SecretKey{
		P:      p.Set(sk.P),
		Q:      q.Set(sk.Q),
		Phi:    phi.Set(sk.Phi),
		PhiInv: phiInv.Set(sk.PhiInv),
		pk:     *sk.pk.Clone(),
	}
}

func (sk SecretKey) GeneratePedersen() (ped *pedersen.Parameters, lambda *big.Int) {
	var s, t *big.Int
	s, t, lambda = sample.Pedersen(sk.pk.N, sk.Phi)
	return &pedersen.Parameters{
		N: sk.pk.N,
		S: s,
		T: t,
	}, lambda
}

func is3mod4(n *big.Int) bool {
	return n.Bit(0) == 1 && n.Bit(1) == 1
}

func (sk SecretKey) Validate() error {
	var n, phi, pMin1, qMin1 big.Int

	// check == 3 (mod 4)
	if !is3mod4(sk.P) {
		return fmt.Errorf("paillier.SecretKey: prime p: %w", ErrNotBlum)
	}
	if !is3mod4(sk.Q) {
		return fmt.Errorf("paillier.SecretKey: prime q: %w", ErrNotBlum)
	}

	// check bit lengths
	const bitsWant = params.BitsBlumPrime
	if bits := sk.P.BitLen(); bits != bitsWant {
		return fmt.Errorf("paillier.SecretKey: prime p have: %d, need %d: %w", bits, bitsWant, ErrPrimeBadLength)
	}
	if bits := sk.Q.BitLen(); bits != bitsWant {
		return fmt.Errorf("paillier.SecretKey: prime q have: %d, need %d: %w", bits, bitsWant, ErrPrimeBadLength)
	}

	// check prime
	if !sk.P.ProbablyPrime(20) {
		return fmt.Errorf("paillier.SecretKey: prime p: %w", ErrNotPrime)
	}
	// check prime
	if !sk.Q.ProbablyPrime(20) {
		return fmt.Errorf("paillier.SecretKey: prime q: %w", ErrNotPrime)
	}

	// check phi = (p-1)(q-1)
	one := big.NewInt(1)
	pMin1.Sub(sk.P, one)
	qMin1.Sub(sk.Q, one)
	phi.Mul(&pMin1, &qMin1)
	if phi.Cmp(sk.Phi) != 0 {
		return ErrWrongPhi
	}

	// check ϕ * phiInv = 1 (mod N)
	n.Mul(sk.P, sk.Q)
	phi.Mul(&phi, sk.PhiInv)
	phi.Mod(&phi, &n)
	if phi.Cmp(one) != 0 {
		return ErrWrongPhiInv
	}

	// Compare N
	if n.Cmp(sk.pk.N) != 0 {
		return ErrModulusMismatch
	}

	// check public key too
	err := sk.PublicKey().Validate()
	if err != nil {
		return fmt.Errorf("paillier.SecretKey: invalid public key: %w", err)
	}
	return nil
}
