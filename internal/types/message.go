package types

import (
	"io"
)

// SigningMessage wraps a byte slice representing a message to be signed.
type SigningMessage []byte

// WriteTo implements io.WriterTo interface.
func (t SigningMessage) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(t)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain.
func (t SigningMessage) Domain() string {
	if t == nil {
		return "Empty Message"
	}
	return "Signature Message"
}
