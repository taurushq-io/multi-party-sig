package paillier

import (
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

type PublicKey struct {
	// N = p⋅q
	N *big.Int
	// nSquared = N²
	nSquared *big.Int
	// nHalf = (N-1) / 2
	nHalf *big.Int
}

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
// If nonce = nil, the a fresh nonce is sampled.
// The nonce used to encrypt is always returned.
//
// ct = (1+N)ᵐρᴺ (mod N²)
func (pk *PublicKey) Enc(m, nonce *big.Int) (*Ciphertext, *big.Int) {
	ct := NewCiphertext()
	return ct.Enc(pk, m, nonce)
}

// Equal returns true if pk = other.
func (pk *PublicKey) Equal(other *PublicKey) bool {
	return pk.N.Cmp(other.N) == 0
}

// Nonce returns a suitable nonce ρ for encryption.
// ρ ∈ ℤₙˣ
func (pk *PublicKey) Nonce() *big.Int {
	return sample.UnitModN(pk.N)
}

func (pk *PublicKey) Validate() error {
	// log₂(N) = BitsPaillier
	if bits := pk.N.BitLen(); bits != params.BitsPaillier {
		return fmt.Errorf("paillier.PublicKey: have: %d, need %d: %w", bits, params.BitsPaillier, ErrPaillierLength)
	}
	if pk.N.Bit(0) != 1 {
		return ErrPaillierEven
	}

	return nil
}

func (pk *PublicKey) Clone() *PublicKey {
	var N, NSquared, nHalf big.Int
	return &PublicKey{
		N:        N.Set(pk.N),
		nSquared: NSquared.Set(pk.nSquared),
		nHalf:    nHalf.Set(pk.nHalf),
	}
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (pk *PublicKey) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, params.BytesPaillier)
	pk.N.FillBytes(buf)
	n, err := w.Write(buf)
	return int64(n), err
}
