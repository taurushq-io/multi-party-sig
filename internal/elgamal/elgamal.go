package elgamal

import (
	"crypto/rand"
	"io"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

type (
	PublicKey = curve.Point
	Nonce     = curve.Scalar
)

type Ciphertext struct {
	// L = nonce⋅G
	L curve.Point
	// M = message⋅G + nonce⋅public
	M curve.Point
}

// Encrypt returns the encryption of `message` as (L=nonce⋅G, M=message⋅G + nonce⋅public), as well as the `nonce`.
func Encrypt(public PublicKey, message curve.Scalar) (*Ciphertext, Nonce) {
	group := public.Curve()
	nonce := sample.Scalar(rand.Reader, group)
	L := nonce.ActOnBase()
	M := message.ActOnBase().Add(nonce.Act(public))
	return &Ciphertext{
		L: L,
		M: M,
	}, nonce
}

// Valid returns true if the ciphertext passes basic validation.
func (c *Ciphertext) Valid() bool {
	if c == nil || c.L == nil || c.L.IsIdentity() ||
		c.M == nil || c.M.IsIdentity() {
		return false
	}
	return true
}

func Empty(group curve.Curve) *Ciphertext {
	return &Ciphertext{
		L: group.NewPoint(),
		M: group.NewPoint(),
	}
}

func (c *Ciphertext) WriteTo(w io.Writer) (int64, error) {
	var total int64
	var n int

	buf, err := c.L.MarshalBinary()
	if err != nil {
		return 0, err
	}
	n, err = w.Write(buf)
	total += int64(n)
	if err != nil {
		return total, err
	}

	buf, err = c.M.MarshalBinary()
	if err != nil {
		return 0, err
	}
	n, err = w.Write(buf)
	total += int64(n)
	if err != nil {
		return total, err
	}

	return total, nil
}

func (Ciphertext) Domain() string {
	return "ElGamal Ciphertext"
}
