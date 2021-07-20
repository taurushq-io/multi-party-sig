package paillier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

var (
	ErrPaillierLength = errors.New("wrong number bit length of Paillier modulus N")
	ErrPaillierEven   = errors.New("modulus N is even")
)

var oneNat *safenum.Nat = new(safenum.Nat).SetUint64(1)

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

// N is the public modulus making up this key
func (pk *PublicKey) N() *big.Int {
	return pk.n.Big()
}

// NewPublicKey returns an initialized paillier.PublicKey and computes N, N² and (N-1)/2.
// The input n is copied.
func NewPublicKey(n *big.Int) *PublicKey {
	nNat := new(safenum.Nat).SetBig(n, n.BitLen())
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

// Enc returns the encryption of m under the public key pk.
// The nonce used to encrypt is returned.
//
// The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise
//
// ct = (1+N)ᵐρᴺ (mod N²)
func (pk PublicKey) Enc(m *big.Int) (*Ciphertext, *big.Int) {
	cipher, nonce := pk.encNat(new(safenum.Int).SetBig(m, m.BitLen()))
	return cipher, nonce.Big()
}

// Enc, but with Nat arguments
func (pk PublicKey) encNat(m *safenum.Int) (*Ciphertext, *safenum.Nat) {
	nonce := sample.UnitModNNat(rand.Reader, pk.n)
	return pk.encWithNonceNat(m, nonce), nonce
}

// EncWithNonce returns the encryption of m under the public key pk.
// The nonce is not returned.
//
// The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise
//
// ct = (1+N)ᵐρᴺ (mod N²)
func (pk PublicKey) EncWithNonce(m, nonce *big.Int) *Ciphertext {
	mInt := new(safenum.Int).SetBig(m, m.BitLen())
	nonceNat := new(safenum.Nat).SetBig(nonce, nonce.BitLen())

	return pk.encWithNonceNat(mInt, nonceNat)
}

// EncWithNonce, but with Nat
func (pk PublicKey) encWithNonceNat(m *safenum.Int, nonce *safenum.Nat) *Ciphertext {
	if m.CheckInRange(pk.n) != 1 {
		panic("paillier.Encrypt: tried to encrypt message outside of range [-(N-1)/2, …, (N-1)/2]")
	}
	out := NewCiphertext()

	// N + 1
	out.C.SetNat(pk.nPlusOne)
	// (N+1)ᵐ mod N²
	out.C.ExpI(out.C, m, pk.nSquared)
	// rho ^ N mod N²
	rhoN := new(safenum.Nat).Exp(nonce, pk.nNat, pk.nSquared)
	// (N+1)ᵐ rho ^ N
	out.C.ModMul(out.C, rhoN, pk.nSquared)

	return out
}

// Equal returns true if pk = other.
func (pk PublicKey) Equal(other *PublicKey) bool {
	_, eq, _ := pk.n.Cmp(other.n)
	return eq == 1
}

// Validate returns an error if the bit length of N is wrong or if it is even.
func (pk PublicKey) Validate() error {
	// log₂(N) = BitsPaillier
	if bits := pk.n.BitLen(); bits != params.BitsPaillier {
		return fmt.Errorf("paillier.publicKey: have: %d, need %d: %w", bits, params.BitsPaillier, ErrPaillierLength)
	}
	if pk.nNat.Byte(0)&1 != 1 {
		return ErrPaillierEven
	}

	return nil
}

// ValidateCiphertexts checks if all ciphertexts are in the correct range and coprime to N²
// ct ∈ [1, …, N²-1] AND GCD(ct,N²) = 1
func (pk PublicKey) ValidateCiphertexts(cts ...*Ciphertext) bool {
	for _, ct := range cts {
		_, _, lt := ct.C.CmpMod(pk.nSquared)
		if lt != 1 {
			return false
		}
		if ct.C.IsUnit(pk.nSquared) != 1 {
			return false
		}
	}
	return true
}

// Clone performs a deep copy of the public key
func (pk PublicKey) Clone() *PublicKey {
	return &PublicKey{
		n:        pk.n,
		nNat:     pk.nNat.Clone(),
		nSquared: pk.nSquared,
		nPlusOne: pk.nPlusOne.Clone(),
	}
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (pk PublicKey) WriteTo(w io.Writer) (int64, error) {
	buf := pk.n.Bytes()
	n, err := w.Write(buf)
	return int64(n), err
}

// Domain implements WriterToWithDomain, and separates this type within hash.Hash.
func (PublicKey) Domain() string {
	return "Paillier PublicKey"
}
