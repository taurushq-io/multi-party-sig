package paillier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

var (
	ErrPaillierLength = errors.New("wrong number bit length of Paillier modulus N")
	ErrPaillierEven   = errors.New("modulus N is even")
)

var oneNat = new(safenum.Nat).SetUint64(1)

// PublicKey is a Paillier public key. It is represented by a modulus N.
type PublicKey struct {
	// n = p⋅q
	n *safenum.Modulus
	// These values are cached out of convenience, and performance
	nNat *safenum.Nat
	// nSquared = n²
	nSquared *safenum.Modulus
	// nPlusOne = n + 1
	nPlusOne *safenum.Nat
}

// N is the public modulus making up this key.
func (pk *PublicKey) N() *safenum.Modulus {
	return pk.n
}

// NewPublicKey returns an initialized paillier.PublicKey and caches N, N² and (N-1)/2.
func NewPublicKey(n *safenum.Modulus) *PublicKey {
	nNat := n.Nat()
	nSquared := new(safenum.Nat).Mul(nNat, nNat, -1)
	nPlusOne := new(safenum.Nat).Add(nNat, oneNat, -1)
	// Tightening is fine, since n is public
	nPlusOne.Resize(nPlusOne.TrueLen())

	return &PublicKey{
		n:        safenum.ModulusFromNat(nNat),
		nNat:     nNat,
		nSquared: safenum.ModulusFromNat(nSquared),
		nPlusOne: nPlusOne,
	}
}

// ValidateN performs basic checks to make sure the modulus is valid:
// - log₂(n) = params.BitsPaillier.
// - n is odd.
func ValidateN(n *safenum.Modulus) error {
	// log₂(N) = BitsPaillier
	nBig := n.Big()
	if bits := nBig.BitLen(); bits != params.BitsPaillier {
		return fmt.Errorf("have: %d, need %d: %w", bits, params.BitsPaillier, ErrPaillierLength)
	}
	if nBig.Bit(0) != 1 {
		return ErrPaillierEven
	}
	return nil
}

// Enc returns the encryption of m under the public key pk.
// The nonce used to encrypt is returned.
//
// The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise.
//
// ct = (1+N)ᵐρᴺ (mod N²).
func (pk PublicKey) Enc(m *safenum.Int) (*Ciphertext, *safenum.Nat) {
	nonce := sample.UnitModN(rand.Reader, pk.n)
	return pk.EncWithNonce(m, nonce), nonce
}

// EncWithNonce returns the encryption of m under the public key pk.
// The nonce is not returned.
//
// The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise
//
// ct = (1+N)ᵐρᴺ (mod N²).
func (pk PublicKey) EncWithNonce(m *safenum.Int, nonce *safenum.Nat) *Ciphertext {
	if m.CheckInRange(pk.n) != 1 {
		panic("paillier.Encrypt: tried to encrypt message outside of range [-(N-1)/2, …, (N-1)/2]")
	}
	c := new(safenum.Nat)

	// N + 1
	c.SetNat(pk.nPlusOne)
	// (N+1)ᵐ mod N²
	c.ExpI(c, m, pk.nSquared)
	// rho ^ N mod N²
	rhoN := new(safenum.Nat).Exp(nonce, pk.nNat, pk.nSquared)
	// (N+1)ᵐ rho ^ N
	c.ModMul(c, rhoN, pk.nSquared)

	return &Ciphertext{c: c}
}

// Equal returns true if pk ≡ other.
func (pk PublicKey) Equal(other *PublicKey) bool {
	_, eq, _ := pk.n.Cmp(other.n)
	return eq == 1
}

// ValidateCiphertexts checks if all ciphertexts are in the correct range and coprime to N²
// ct ∈ [1, …, N²-1] AND GCD(ct,N²) = 1.
func (pk PublicKey) ValidateCiphertexts(cts ...*Ciphertext) bool {
	for _, ct := range cts {
		_, _, lt := ct.c.CmpMod(pk.nSquared)
		if lt != 1 {
			return false
		}
		if ct.c.IsUnit(pk.nSquared) != 1 {
			return false
		}
	}
	return true
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (pk *PublicKey) WriteTo(w io.Writer) (int64, error) {
	if pk == nil {
		return 0, io.ErrUnexpectedEOF
	}
	buf := pk.n.Bytes()
	n, err := w.Write(buf)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (PublicKey) Domain() string {
	return "Paillier PublicKey"
}
