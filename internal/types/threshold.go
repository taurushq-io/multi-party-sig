package types

import (
	"encoding/binary"
	"io"
)

// ThresholdWrapper wraps a uint32 and enables writing with domain.
type ThresholdWrapper uint32

// WriteTo implements io.WriterTo interface.
func (t ThresholdWrapper) WriteTo(w io.Writer) (int64, error) {
	intBuffer := make([]byte, 4)
	binary.BigEndian.PutUint32(intBuffer, uint32(t))
	n, err := w.Write(intBuffer)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain.
func (ThresholdWrapper) Domain() string { return "Threshold" }
