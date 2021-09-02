package paillier

import (
	"crypto/rand"
	"io"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

// Ciphertext represents an integer of the for (1+N)ᵐρᴺ (mod N²), representing the encryption of m ∈ ℤₙˣ.
type Ciphertext struct {
	c *safenum.Nat
}

// Add sets ct to the homomorphic sum ct ⊕ ct₂.
// ct ← ct•ct₂ (mod N²).
func (ct *Ciphertext) Add(pk *PublicKey, ct2 *Ciphertext) *Ciphertext {
	if ct2 == nil {
		return ct
	}

	ct.c.ModMul(ct.c, ct2.c, pk.nSquared.Modulus)

	return ct
}

// Mul sets ct to the homomorphic multiplication of k ⊙ ct.
// ct ← ctᵏ (mod N²).
func (ct *Ciphertext) Mul(pk *PublicKey, k *safenum.Int) *Ciphertext {
	if k == nil {
		return ct
	}

	ct.c = pk.nSquared.ExpI(ct.c, k)

	return ct
}

// Equal check whether ct ≡ ctₐ (mod N²).
func (ct *Ciphertext) Equal(ctA *Ciphertext) bool {
	return ct.c.Eq(ctA.c) == 1
}

// Clone returns a deep copy of ct.
func (ct Ciphertext) Clone() *Ciphertext {
	c := new(safenum.Nat)
	c.SetNat(ct.c)
	return &Ciphertext{c: c}
}

// Randomize multiplies the ciphertext's nonce by a newly generated one.
// ct ← ct ⋅ nonceᴺ (mod N²).
// If nonce is nil, a random one is generated.
// The receiver is updated, and the nonce update is returned.
func (ct *Ciphertext) Randomize(pk *PublicKey, nonce *safenum.Nat) *safenum.Nat {
	if nonce == nil {
		nonce = sample.UnitModN(rand.Reader, pk.n.Modulus)
	}
	// c = c*r^N
	tmp := pk.nSquared.Exp(nonce, pk.nNat)
	ct.c.ModMul(ct.c, tmp, pk.nSquared.Modulus)
	return nonce
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (ct *Ciphertext) WriteTo(w io.Writer) (int64, error) {
	if ct == nil {
		return 0, io.ErrUnexpectedEOF
	}
	buf := make([]byte, params.BytesCiphertext)
	ct.c.FillBytes(buf)
	n, err := w.Write(buf)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (*Ciphertext) Domain() string {
	return "Paillier Ciphertext"
}

func (ct *Ciphertext) MarshalBinary() ([]byte, error) {
	return ct.c.MarshalBinary()
}

func (ct *Ciphertext) UnmarshalBinary(data []byte) error {
	ct.c = new(safenum.Nat)
	return ct.c.UnmarshalBinary(data)
}

func (ct *Ciphertext) Nat() *safenum.Nat {
	return new(safenum.Nat).SetNat(ct.c)
}
