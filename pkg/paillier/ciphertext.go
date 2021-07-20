package paillier

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/internal/proto"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

// Add sets ct to the homomorphic sum ct ct₁ ⊕ ct₂.
// ct = ct₁•ct₂ (mod N²)
func (ct *Ciphertext) Add(pk *PublicKey, otherCt *Ciphertext) *Ciphertext {
	if otherCt == nil {
		return ct
	}

	ct.C.ModMul(ct.C.Nat, otherCt.C.Nat, pk.nSquared)

	return ct
}

// Mul sets ct to the homomorphic multiplication of k ⊙ ctₐ
// ct = ctᵏ (mod N²)
func (ct *Ciphertext) Mul(pk *PublicKey, k *big.Int) *Ciphertext {
	if k == nil {
		return ct
	}

	kInt := new(safenum.Int).SetBig(k, k.BitLen())
	ct.C.ExpI(ct.C.Nat, kInt, pk.nSquared)

	return ct
}

// Equal check whether ct ≡ ctₐ (mod N²)
func (ct *Ciphertext) Equal(ctA *Ciphertext) bool {
	return ct.C.Eq(ctA.C.Nat) == 0
}

// Clone returns a deep copy of ct
func (ct Ciphertext) Clone() *Ciphertext {
	c := NewCiphertext()
	c.C.SetNat(ct.C.Nat)
	return c
}

// Randomize multiplies the ciphertext's nonce by a newly generated one.
// ct *= nonceᴺ for some nonce either given or generated here (if nonce = nil).
// The updated receiver is returned, as well as the nonce update
func (ct *Ciphertext) Randomize(pk *PublicKey, nonce *big.Int) *big.Int {
	nonceNat := new(safenum.Nat)
	if nonce == nil {
		nonceNat = sample.UnitModNNat(rand.Reader, pk.n)
	} else {
		nonceNat.SetBig(nonce, nonce.BitLen())
	}
	// c = c*r^N
	nonceNat.Exp(nonceNat, pk.nNat, pk.nSquared)
	ct.C.ModMul(ct.C.Nat, nonceNat, pk.nSquared)
	return nonce
}

func NewCiphertext() *Ciphertext {
	return &Ciphertext{C: &proto.NatMarshaller{new(safenum.Nat)}}
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (ct *Ciphertext) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, params.BytesCiphertext)
	ct.C.FillBytes(buf)
	n, err := w.Write(buf)
	return int64(n), err
}

// Domain implements WriterToWithDomain, and separates this type within hash.Hash.
func (*Ciphertext) Domain() string {
	return "Paillier Ciphertext"
}
