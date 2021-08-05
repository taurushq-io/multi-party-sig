package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/taurusgroup/multi-party-sig/internal/params"
)

// IntSliceCaster handles big int operations.
type IntSliceCaster struct{}

const prefixSize = 4

type IntSlice = []*big.Int

// Equal returns true if the provided big ints are equal.
func (c *IntSliceCaster) Equal(a, b *IntSlice) bool {
	if a == nil {
		return b == nil
	}
	if len(*a) != len(*b) {
		return false
	}
	for i, ai := range *a {
		bi := (*b)[i]
		if (ai == nil) != (bi == nil) {
			return false
		}
		if ai == nil {
			continue
		}
		if ai.Cmp(bi) != 0 {
			return false
		}
	}
	return true
}

// Size returns the size of a big int.
func (c *IntSliceCaster) Size(a *IntSlice) int {
	if a == nil {
		return 1
	}
	// 4 bytes for uint32 size
	return prefixSize + len(*a)*params.BytesPaillier
}

// MarshalTo marshals the first parameter to the second one.
func (c *IntSliceCaster) MarshalTo(a *IntSlice, buf []byte) (int, error) {
	for _, ai := range *a {
		if ai == nil {
			return 0, errors.New("all big.Int in a must be non nil")
		}
		if ai.BitLen() > params.BitsIntModN {
			return 0, errors.New("all big.Int in a must be at most params.BitsPaillier bits")
		}
	}
	if len(buf) < prefixSize+len(*a)*params.BytesIntModN {
		//todo fix err
		return 0, errors.New("invalid length")
	}
	binary.BigEndian.PutUint32(buf, uint32(len(*a)))

	written := prefixSize
	for _, ai := range *a {
		ai.FillBytes(buf[written : written+params.BytesIntModN])
		written += params.BytesIntModN
	}
	return written, nil
}

// Unmarshal unmarshalls the parameter to a big int.
func (c *IntSliceCaster) Unmarshal(buf []byte) (*IntSlice, error) {
	if len(buf) == 0 {
		return nil, fmt.Errorf("bad input")
	}
	if len(buf) < prefixSize {
		return nil, errors.New("buf does not contain a prefix")
	}

	l := binary.BigEndian.Uint32(buf)
	if uint32(len(buf)) < prefixSize+l*params.BytesIntModN {
		return nil, errors.New("buf contains less data than what the prefix says")
	}

	ret := make(IntSlice, l)

	read := prefixSize
	for i := range ret {
		ret[i] = new(big.Int).SetBytes(buf[read : read+params.BytesIntModN])
		read += params.BytesIntModN
	}

	return &ret, nil
}

// NewPopulated returns a new instance of a big int, pre-populated with a zero.
func (c *IntSliceCaster) NewPopulated() *IntSlice {
	return &IntSlice{big.NewInt(0)}
}
