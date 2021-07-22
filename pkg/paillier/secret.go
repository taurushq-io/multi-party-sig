package paillier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/cronokirby/safenum"
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

func NewSecretKeyFromPrimes(P, Q *big.Int) *SecretKey {
	p := new(safenum.Nat).SetBig(P, P.BitLen())
	q := new(safenum.Nat).SetBig(Q, Q.BitLen())

	n := new(safenum.Nat).Mul(p, q, -1)
	nMod := safenum.ModulusFromNat(n)

	p.Sub(p, oneNat, -1)
	q.Sub(q, oneNat, -1)
	phi := new(safenum.Nat).Mul(p, q, -1)
	// ϕ⁻¹ mod N
	phiInv := new(safenum.Nat).ModInverse(phi, nMod)

	p.SetBig(P, P.BitLen())
	q.SetBig(Q, Q.BitLen())

	return &SecretKey{
		p:         p,
		q:         q,
		phi:       phi,
		phiInv:    phiInv,
		PublicKey: NewPublicKey(n.Big()),
	}
}

// Dec decrypts c and returns the plaintext m ∈ ± (N-2)/2.
// It returns an error if gcd(c, N²) != 1 or if c is not in [1, N²-1].
func (sk *SecretKey) Dec(ct *Ciphertext) (*big.Int, error) {
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
	return new(safenum.Int).SetModSymmetric(result, n).Big(), nil
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
	return &pedersen.Parameters{
		N: sk.PublicKey.n.Big(),
		S: s.Big(),
		T: t.Big(),
	}, lambda
}

func is3mod4(n *safenum.Nat) bool {
	return n.Byte(0)&0b11 == 3
}

func (sk SecretKey) Validate() error {
	// check == 3 (mod 4)
	if !is3mod4(sk.p) {
		return fmt.Errorf("paillier.SecretKey: prime p: %w", ErrNotBlum)
	}
	if !is3mod4(sk.q) {
		return fmt.Errorf("paillier.SecretKey: prime q: %w", ErrNotBlum)
	}

	// check bit lengths
	const bitsWant = params.BitsBlumPrime
	// Technically, this leaks the number of bits, but this is fine, since returning
	// an error asserts this number statically, anyways.
	if bits := sk.p.TrueLen(); bits != bitsWant {
		return fmt.Errorf("paillier.SecretKey: prime p have: %d, need %d: %w", bits, bitsWant, ErrPrimeBadLength)
	}
	if bits := sk.q.TrueLen(); bits != bitsWant {
		return fmt.Errorf("paillier.SecretKey: prime q have: %d, need %d: %w", bits, bitsWant, ErrPrimeBadLength)
	}

	// Hopefully this doesn't leak too much information about p or q
	// check prime
	if !sk.p.Big().ProbablyPrime(20) {
		return fmt.Errorf("paillier.SecretKey: prime p: %w", ErrNotPrime)
	}
	// check prime
	if !sk.q.Big().ProbablyPrime(20) {
		return fmt.Errorf("paillier.SecretKey: prime q: %w", ErrNotPrime)
	}

	// check phi = (p-1)(q-1)
	pMinus1 := new(safenum.Nat).Sub(sk.p, oneNat, -1)
	qMinus1 := new(safenum.Nat).Sub(sk.q, oneNat, -1)
	phi := new(safenum.Nat).Mul(pMinus1, qMinus1, -1)
	if phi.Eq(sk.phi) != 1 {
		return ErrWrongPhi
	}

	nNat := new(safenum.Nat).Mul(sk.p, sk.q, -1)
	// Compare N
	n := safenum.ModulusFromNat(nNat)
	_, nEqual, _ := n.Cmp(sk.PublicKey.n)
	if nEqual != 1 {
		return ErrModulusMismatch
	}

	// check ϕ * phiInv = 1 (mod N)
	phi.ModMul(phi, sk.phiInv, n)
	if phi.Eq(oneNat) != 1 {
		return ErrWrongPhiInv
	}

	// check public key too
	err := sk.PublicKey.Validate()
	if err != nil {
		return fmt.Errorf("paillier.SecretKey: invalid public key: %w", err)
	}
	return nil
}
