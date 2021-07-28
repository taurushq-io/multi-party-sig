package paillier

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

var (
	ErrPrimeBadLength = errors.New("prime factor is not the right length")
	ErrNotBlum        = errors.New("prime factor is not equivalent to 3 (mod 4)")
	ErrNotPrime       = errors.New("supposed prime factor is not prime")
	ErrNotSafePrime   = errors.New("supposed prime factor is not a safe prime")
)

// SecretKey is the secret key corresponding to a Public Paillier Key.
//
// A public key is a modulus N, and the secret key contains the information
// needed to factor N into two primes, P and Q. This allows us to decrypt
// values encrypted using this modulus.
type SecretKey struct {
	*PublicKey
	// p, q such that N = p⋅q
	p, q *safenum.Nat
	// phi = ϕ = (p-1)(q-1)
	phi *safenum.Nat
	// phiInv = ϕ⁻¹ mod N
	phiInv *safenum.Nat
}

// P returns the first of the two factors composing this key.
func (sk *SecretKey) P() *safenum.Nat {
	return sk.p
}

// Q returns the second of the two factors composing this key.
func (sk *SecretKey) Q() *safenum.Nat {
	return sk.q
}

// Phi returns ϕ = (P-1)(Q-1).
//
// This is the result of the totient function ϕ(N), where N = P⋅Q
// is our public key. This function counts the number of units mod N.
//
// This quantity is useful in ZK proofs.
func (sk *SecretKey) Phi() *safenum.Nat {
	return sk.phi
}

func KeyGen() (pk *PublicKey, sk *SecretKey) {
	sk = NewSecretKey()
	pk = sk.PublicKey
	return
}

func NewSecretKey() *SecretKey {
	return NewSecretKeyFromPrimes(sample.Paillier(rand.Reader))
}

func NewSecretKeyFromPrimes(P, Q *safenum.Nat) *SecretKey {
	// TODO validate primes here ?
	n := new(safenum.Nat).Mul(P, Q, -1)
	nMod := safenum.ModulusFromNat(n)

	pMinus1 := new(safenum.Nat).Sub(P, oneNat, -1)
	qMinus1 := new(safenum.Nat).Sub(Q, oneNat, -1)

	phi := new(safenum.Nat).Mul(pMinus1, qMinus1, -1)
	// ϕ⁻¹ mod N
	phiInv := new(safenum.Nat).ModInverse(phi, nMod)

	pk, err := NewPublicKey(n.Big())
	if err != nil {
		//todo handle error
	}

	return &SecretKey{
		p:         P,
		q:         Q,
		phi:       phi,
		phiInv:    phiInv,
		PublicKey: pk,
	}
}

// Dec decrypts c and returns the plaintext m ∈ ± (N-2)/2.
// It returns an error if gcd(c, N²) != 1 or if c is not in [1, N²-1].
func (sk *SecretKey) Dec(ct *Ciphertext) (*safenum.Int, error) {
	n := sk.PublicKey.n
	nSquared := sk.PublicKey.nSquared

	if !sk.PublicKey.ValidateCiphertexts(ct) {
		return nil, errors.New("paillier: failed to decrypt invalid ciphertext")
	}

	phi := sk.phi
	phiInv := sk.phiInv

	result := new(safenum.Nat)
	// r = c^Phi 						(mod N²)
	result.Exp(ct.C.Nat, phi, nSquared)
	// r = c^Phi - 1
	result.Sub(result, oneNat, -1)
	// r = [(c^Phi - 1)/N]
	result.Div(result, n, -1)
	// r = [(c^Phi - 1)/N] • Phi^-1		(mod N)
	result.ModMul(result, phiInv, n)

	// see 6.1 https://www.iacr.org/archive/crypto2001/21390136.pdf
	return new(safenum.Int).SetModSymmetric(result, n), nil
}

func (sk *SecretKey) Clone() *SecretKey {
	return &SecretKey{
		p:         sk.p.Clone(),
		q:         sk.q.Clone(),
		phi:       sk.phi.Clone(),
		phiInv:    sk.phiInv.Clone(),
		PublicKey: sk.PublicKey.Clone(),
	}
}

func (sk SecretKey) GeneratePedersen() (*pedersen.Parameters, *safenum.Nat) {
	s, t, lambda := sample.Pedersen(rand.Reader, sk.phi, sk.PublicKey.n)
	ped, _ := pedersen.New(sk.PublicKey.n.Big(), s.Big(), t.Big())
	// TODO handle error ?
	return ped, lambda
}

func ValidatePrime(p *safenum.Nat) error {
	// check bit lengths
	const bitsWant = params.BitsBlumPrime
	// Technically, this leaks the number of bits, but this is fine, since returning
	// an error asserts this number statically, anyways.
	if bits := p.TrueLen(); bits != bitsWant {
		return fmt.Errorf("invalid prime size: have: %d, need %d: %w", bits, bitsWant, ErrPrimeBadLength)
	}
	// check == 3 (mod 4)
	if p.Byte(0)&0b11 != 3 {
		return ErrNotBlum
	}
	// Hopefully this doesn't leak too much information about p or q
	// check prime
	if !p.Big().ProbablyPrime(1) {
		return ErrNotPrime
	}

	// check (p-1)/2 is prime
	pMinus1Div2 := new(safenum.Nat).Sub(p, oneNat, -1)
	pMinus1Div2.Rsh(p, 1, -1)
	if !pMinus1Div2.Big().ProbablyPrime(1) {
		return ErrNotSafePrime
	}
	return nil
}
