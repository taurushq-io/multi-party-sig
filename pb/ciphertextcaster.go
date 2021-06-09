package pb

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

// CiphertextCaster handles ciphertext operations
type CiphertextCaster struct{}

// Equal returns true if the provided ciphertexts are equal
func (c *CiphertextCaster) Equal(a, b *paillier.Ciphertext) bool {
	if a == nil {
		return b == nil
	}
	return a.Equal(b)
}

// Size returns the size of a ciphertext
func (c *CiphertextCaster) Size(a *paillier.Ciphertext) int {
	if a == nil {
		return 1
	}
	return params.BytesCiphertext
}

// MarshalTo marshals the first parameter to the second one
func (c *CiphertextCaster) MarshalTo(a *paillier.Ciphertext, buf []byte) (int, error) {
	if a == nil {
		buf[0] = 0
		return 1, nil
	}
	bytes := make([]byte, params.BytesCiphertext)
	a.Int().FillBytes(bytes)
	if len(buf) < len(bytes) {
		//todo fix err
		return 0, errors.New("invalid")
	}
	copy(buf, bytes)
	return params.BytesCiphertext, nil
}

// Unmarshal unmarshalls the parameter to a ciphertext
func (c *CiphertextCaster) Unmarshal(buf []byte) (*paillier.Ciphertext, error) {
	switch len(buf) {
	case 0:
		return nil, fmt.Errorf("bad input")
	case 1:
		return nil, nil
	}
	ct := paillier.NewCiphertext()
	ct.Int().SetBytes(buf[:params.BytesCiphertext])
	return ct, nil
}

// NewPopulated returns a new instance of a ciphertext, pre-populated with a zero
func (c *CiphertextCaster) NewPopulated() *paillier.Ciphertext {
	return paillier.NewCiphertext()
}
