package types

import (
	"io"
)

// MessageWrapper wraps
type MessageWrapper []byte

// WriteTo implements io.WriterTo interface.
func (t MessageWrapper) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(t)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain.
func (t MessageWrapper) Domain() string {
	if t == nil {
		return "Empty Message"
	}
	return "Signature Message"
}
