package types

import (
	"io"
)

// RoundNumber is the index of the current round.
// Starts at zero
type RoundNumber uint16

// ProtocolID defines a unique identifier for a protocol.
// It will be written as {shorthand for paper}/{protocol function}-{version}-{broadcast type}
type ProtocolID string

// WriteTo implements io.WriterTo interface.
func (pid ProtocolID) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write([]byte(pid))
	return int64(n), err
}

// Domain implements writer.WriterToWithDomain
func (ProtocolID) Domain() string {
	return "Protocol ID"
}
