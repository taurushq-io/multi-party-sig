package proto

import (
	"errors"
	"math/big"

	"github.com/cronokirby/safenum"
)

// NatMarshaller is a wrapper used to direct serialization of safenum.Nat
type NatMarshaller struct{}

// Equal returns true if the provided Nat are equal
func (*NatMarshaller) Equal(a, b *safenum.Nat) bool {
	if a == nil {
		return b == nil
	}
	return a.Eq(b) == 1
}

// Size returns the size of a Nat
func (*NatMarshaller) Size(a *safenum.Nat) int {
	if a == nil {
		return 0
	}
	return (a.AnnouncedLen() + 7) / 8
}

// MarshalTo marshals the first parameter to the second one
func (marshaller *NatMarshaller) MarshalTo(a *safenum.Nat, buf []byte) (int, error) {
	size := marshaller.Size(a)
	if len(buf) < size {
		return 0, errors.New("invalid: too small")
	}
	a.FillBytes(buf)
	return size, nil
}

// Unmarshal unmarshalls the parameter to a Nat
func (*NatMarshaller) Unmarshal(buf []byte) (*safenum.Nat, error) {
	out := new(safenum.Nat).SetBytes(buf)
	return out, nil
}

// NewPopulated returns a new instance of a Nat, pre-populated with a zero
func (*NatMarshaller) NewPopulated() *big.Int {
	return big.NewInt(0)
}
