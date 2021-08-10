package types

import (
	"io"
)

// RoundNumber is the index of the current round.
// 0 indicates the output round, 1 is the first round.
type RoundNumber uint16

// ProtocolID defines a unique identifier for a protocol.
// It will be written as {shorthand for paper}/{protocol function}-{version}-{broadcast type}.
type ProtocolID string

// WriteTo implements io.WriterTo interface.
func (pid ProtocolID) WriteTo(w io.Writer) (int64, error) {
	if pid == "" {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := w.Write([]byte(pid))
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain.
func (ProtocolID) Domain() string {
	return "Protocol ID"
}
