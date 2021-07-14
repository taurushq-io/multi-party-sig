package paillier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

var (
	ErrPaillierLength = errors.New("wrong number bit length of Paillier modulus N")
	ErrPaillierEven   = errors.New("modulus N is even")
)

// PublicKey is a Paillier public key. It is represented by N and caches N² and (N-1)/2
type PublicKey struct {
	// N = p⋅q
	N *big.Int
	// nSquared = N²
	nSquared *big.Int
	// nHalf = (N-1) / 2
	nHalf *big.Int
}

// NewPublicKey returns an initialized paillier.PublicKey and computes N, N² and (N-1)/2.
// The input n is copied.
func NewPublicKey(n *big.Int) *PublicKey {
	var nNew, nHalf big.Int
	nSquared := newCipherTextInt()
	nSquared.Mul(n, n)
	nHalf.Rsh(n, 1)
	return &PublicKey{
		N:        nNew.Set(n),
		nSquared: nSquared,
		nHalf:    &nHalf,
	}
}

// Enc returns the encryption of m under the public key pk.
// The nonce used to encrypt is returned.
//
// The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise
//
// ct = (1+N)ᵐρᴺ (mod N²)
func (pk PublicKey) Enc(m *big.Int) (*Ciphertext, *big.Int) {
	nonce := sample.UnitModN(rand.Reader, pk.N)
	return pk.EncWithNonce(m, nonce), nonce
}

// EncWithNonce returns the encryption of m under the public key pk.
// The nonce is not returned.
//
// The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise
//
// ct = (1+N)ᵐρᴺ (mod N²)
func (pk PublicKey) EncWithNonce(m, nonce *big.Int) *Ciphertext {
	if m.CmpAbs(pk.nHalf) == 1 {
		panic("paillier.Encrypt: tried to encrypt message outside of range [-(N-1)/2, …, (N-1)/2]")
	}

	ct := NewCiphertext()

	tmp := newCipherTextInt()
	one := big.NewInt(1)

	tmp.Set(pk.N)                 // N
	tmp.Add(tmp, one)             // N + 1
	ct.C.Exp(tmp, m, pk.nSquared) // (N+1)ᵐ mod N²

	tmp.Exp(nonce, pk.N, pk.nSquared) // rho ^ N mod N²

	ct.C.Mul(ct.C, tmp) // (N+1)ᵐ rho ^ N
	ct.C.Mod(ct.C, pk.nSquared)

	return ct
}

// Equal returns true if pk = other.
func (pk PublicKey) Equal(other *PublicKey) bool {
	return pk.N.Cmp(other.N) == 0
}

// Validate returns an error if the bit length of N is wrong or if it is even.
func (pk PublicKey) Validate() error {
	// log₂(N) = BitsPaillier
	if bits := pk.N.BitLen(); bits != params.BitsPaillier {
		return fmt.Errorf("paillier.publicKey: have: %d, need %d: %w", bits, params.BitsPaillier, ErrPaillierLength)
	}
	if pk.N.Bit(0) != 1 {
		return ErrPaillierEven
	}

	return nil
}

// ValidateCiphertexts checks if all ciphertexts are in the correct range and coprime to N²
// ct ∈ [1, …, N²-1] AND GCD(ct,N²) = 1
func (pk PublicKey) ValidateCiphertexts(cts ...*Ciphertext) bool {
	var gcd big.Int
	one := big.NewInt(1)
	for _, ct := range cts {
		if ct.C.Cmp(pk.nSquared) != -1 {
			return false
		}
		gcd.GCD(nil, nil, ct.C, pk.nSquared)
		if gcd.Cmp(one) != 0 {
			return false
		}
		if ct.C.Sign() != 1 {
			return false
		}
	}
	return true
}

// Clone performs a deep copy of the public key
func (pk PublicKey) Clone() *PublicKey {
	var N, NSquared, nHalf big.Int
	return &PublicKey{
		N:        N.Set(pk.N),
		nSquared: NSquared.Set(pk.nSquared),
		nHalf:    nHalf.Set(pk.nHalf),
	}
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (pk PublicKey) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, params.BytesPaillier)
	pk.N.FillBytes(buf)
	n, err := w.Write(buf)
	return int64(n), err
}

// Domain implements WriterToWithDomain, and separates this type within hash.Hash.
func (PublicKey) Domain() string {
	return "Paillier PublicKey"
}
