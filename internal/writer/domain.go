package writer

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

// WriteWithDomain writes out a piece of data, using its domain.
func WriteWithDomain(w io.Writer, object WriterToWithDomain) (int64, error) {
	total := int64(0)
	// Write out `(<domain><data>)`, so that each domain separated piece of data
	// is distinguished from others.
	n, err := w.Write([]byte("("))
	total += int64(n)
	if err != nil {
		return total, err
	}
	n, err = w.Write([]byte(object.Domain()))
	total += int64(n)
	if err != nil {
		return total, err
	}
	n64, err := object.WriteTo(w)
	total += n64
	if err != nil {
		return total, err
	}
	n, err = w.Write([]byte(")"))
	total += int64(n)
	return total, err
}
