// LockedReader wraps an io.Reader to be safe for concurrent reads.
//
// This type implements io.Reader, returning the same output.
//
// This means acquiring a lock whenever a read happens, so be aware of that
// for performance or concurrency reasons.
type LockedReader struct {
	reader io.Reader
	m      sync.Mutex
}

// NewLockedReader creates a LockedReader by wrapping an underlying value.
func NewLockedReader(r io.Reader) *LockedReader {
	// Intentionally not initializing m, since the zero value is ok
	return &LockedReader{reader: r}
}

// Read implements io.Reader for LockedReader
//
// The behavior is to return the same output as the underlying reader. The difference
// is that it's safe to call this function concurrently.
//
// Naturally, when calling this function concurrently, what value ends up getting
// read is raced, but you won't end up reading the same value twice, or otherwise
// messing up the state of the reader.
func (r *LockedReader) Read(p []byte) (int, error) {
	r.m.Lock()
	defer r.m.Unlock()
	return r.reader.Read(p)
}
