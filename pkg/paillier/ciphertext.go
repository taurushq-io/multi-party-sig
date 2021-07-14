package paillier

import (
	"crypto/rand"
	"io"
	"math/big"
	"math/bits"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

const cipherTextWordSize = 4*params.BitsPaillier/bits.UintSize + 8

// Add sets ct to the homomorphic sum ct ct₁ ⊕ ct₂.
// ct = ct₁•ct₂ (mod N²)
func (ct *Ciphertext) Add(pk *PublicKey, otherCt *Ciphertext) *Ciphertext {
	if otherCt == nil {
		return ct
	}
	ct.C.Mul(ct.C, otherCt.C)
	ct.C.Mod(ct.C, pk.nSquared)
	return ct
}

// Mul sets ct to the homomorphic multiplication of k ⊙ ctₐ
// ct = ctᵏ (mod N²)
func (ct *Ciphertext) Mul(pk *PublicKey, k *big.Int) *Ciphertext {
	if k == nil {
		return ct
	}
	ct.C.Exp(ct.C, k, pk.nSquared)
	return ct
}

// Equal check whether ct ≡ ctₐ (mod N²)
func (ct *Ciphertext) Equal(ctA *Ciphertext) bool {
	return ct.C.Cmp(ctA.C) == 0
}

// Clone returns a deep copy of ct
func (ct Ciphertext) Clone() *Ciphertext {
	c := NewCiphertext()
	c.C.Set(ct.C)
	return c
}

// Randomize multiplies the ciphertext's nonce by a newly generated one.
// ct *= nonceᴺ for some nonce either given or generated here (if nonce = nil).
// The updated receiver is returned, as well as the nonce update
func (ct *Ciphertext) Randomize(pk *PublicKey, nonce *big.Int) *big.Int {
	tmp := newCipherTextInt()
	if nonce == nil {
		nonce = sample.UnitModN(rand.Reader, pk.N)
	}
	tmp.Exp(nonce, pk.N, pk.nSquared) // tmp = r^N
	ct.C.Mul(ct.C, tmp)               // ct = ct * tmp
	ct.C.Mod(ct.C, pk.nSquared)       // ct = ct*r^N
	return nonce
}

func NewCiphertext() *Ciphertext {
	buf := make([]big.Word, 0, cipherTextWordSize+2)
	c := new(big.Int).SetBits(buf)
	return &Ciphertext{C: c}
}

func newCipherTextInt() *big.Int {
	tmpBuf := make([]big.Word, 0, cipherTextWordSize)
	var tmp big.Int
	tmp.SetBits(tmpBuf)
	return &tmp
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
