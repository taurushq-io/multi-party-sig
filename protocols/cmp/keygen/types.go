package keygen

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/taurusgroup/multi-party-sig/internal/params"
)

// RID is the unique identifier generated during the keygen.
type RID []byte

func newRID() RID {
	return make(RID, params.SecBytes)
}

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

func (rid RID) Validate() error {
	if l := len(rid); l != params.SecBytes {
		return fmt.Errorf("rid: incorrect length (got %d, expected %d)", l, params.SecBytes)
	}
	return nil
}

func (rid RID) Copy() RID {
	other := newRID()
	copy(other, rid)
	return other
}

// thresholdWrapper wraps a uint32 and enables writing with domain.
type thresholdWrapper uint32

// WriteTo implements io.WriterTo interface.
func (t thresholdWrapper) WriteTo(w io.Writer) (int64, error) {
	intBuffer := make([]byte, 4)
	binary.BigEndian.PutUint32(intBuffer, uint32(t))
	n, err := w.Write(intBuffer)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain.
func (thresholdWrapper) Domain() string { return "Threshold" }
