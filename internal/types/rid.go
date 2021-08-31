package types

import (
	"errors"
	"fmt"
	"io"

	"github.com/taurusgroup/multi-party-sig/internal/params"
)

// RID represents a byte slice of whose size equals the security parameter.
// It can be easily XOR'ed with other RID. An empty slice is considered invalid.
type RID []byte

// EmptyRID returns a zeroed-out RID with
func EmptyRID() RID {
	return make(RID, params.SecBytes)
}

func NewRID(r io.Reader) (RID, error) {
	rid := EmptyRID()
	_, err := io.ReadFull(r, rid)
	return rid, err
}

// XOR modifies the receiver by taking the XOR with the argument.
func (rid RID) XOR(otherRID RID) {
	for b := 0; b < params.SecBytes; b++ {
		rid[b] ^= otherRID[b]
	}
}

// WriteTo implements io.WriterTo interface.
func (rid RID) WriteTo(w io.Writer) (int64, error) {
	if rid == nil {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := w.Write(rid[:])
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain.
func (RID) Domain() string { return "RID" }

// Validate ensure that the RID is the correct length and is not identically 0.
func (rid RID) Validate() error {
	if l := len(rid); l != params.SecBytes {
		return fmt.Errorf("rid: incorrect length (got %d, expected %d)", l, params.SecBytes)
	}
	for _, b := range rid {
		if b != 0 {
			return nil
		}
	}
	return errors.New("rid: rid is 0")
}

func (rid RID) Copy() RID {
	other := EmptyRID()
	copy(other, rid)
	return other
}
