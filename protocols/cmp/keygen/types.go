package keygen

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
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
	n, err := w.Write(rid[:])
	return int64(n), err
}

// Domain implements writer.WriterToWithDomain.
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

type Threshold int64

// WriteTo implements io.WriterTo interface.
func (t Threshold) WriteTo(w io.Writer) (int64, error) {
	intBuffer := make([]byte, 8)
	binary.BigEndian.PutUint64(intBuffer, uint64(t))
	n, err := w.Write(intBuffer)
	return int64(n), err
}

// Domain implements writer.WriterToWithDomain.
func (Threshold) Domain() string { return "Threshold" }
