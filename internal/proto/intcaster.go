package proto

import (
	"errors"
	"fmt"
	"math/big"
)

// IntCaster handles big int operations
type IntCaster struct{}

// Equal returns true if the provided big ints are equal
func (c *IntCaster) Equal(a, b *big.Int) bool {
	if a == nil {
		return b == nil
	}
	return a.Cmp(b) == 0
}

// Size returns the size of a big int
func (c *IntCaster) Size(a *big.Int) int {
	if a == nil {
		return 0
	}
	return 1 + (a.BitLen()+7)/8
}

// MarshalTo marshals the first parameter to the second one
func (c *IntCaster) MarshalTo(a *big.Int, buf []byte) (int, error) {
	bytes, err := a.GobEncode()
	if err != nil {
		return 0, err
	}

	if len(buf) < len(bytes) {
		return 0, errors.New("invalid")
	}
	copy(buf, bytes)
	return len(bytes), nil
}

// Unmarshal unmarshalls the parameter to a big int
func (c *IntCaster) Unmarshal(buf []byte) (*big.Int, error) {
	if len(buf) == 0 {
		return nil, fmt.Errorf("bad input")
	}
	var i big.Int
	if err := i.GobDecode(buf); err != nil {
		return nil, err
	}

	return &i, nil
}

// NewPopulated returns a new instance of a big int, pre-populated with a zero
func (c *IntCaster) NewPopulated() *big.Int {
	return big.NewInt(0)
}
