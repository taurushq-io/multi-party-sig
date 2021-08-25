package hash

import "io"

// WriterToWithDomain represents a type writing itself, and knowing its domain.
//
// Providing a domain string lets us distinguish the output of different types
// implementing this same interface.
type WriterToWithDomain interface {
	io.WriterTo

	// Domain returns a context string, which should be unique for each implementor
	Domain() string
}

// BytesWithDomain is a useful wrapper to annotate some chunk of data with a domain.
//
// The intention is to wrap some data using this struct, and then call WriteWithDomain,
// or use this struct as a WriterToWithDomain somewhere else.
type BytesWithDomain struct {
	TheDomain string
	Bytes     []byte
}

// WriteTo implements io.WriterTo.
func (b BytesWithDomain) WriteTo(w io.Writer) (int64, error) {
	if b.Bytes == nil {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := w.Write(b.Bytes)
	return int64(n), err
}

// Domain implements WriterToWithDomain.
func (b BytesWithDomain) Domain() string {
	return b.TheDomain
}
