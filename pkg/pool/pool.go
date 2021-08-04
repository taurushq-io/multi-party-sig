package pool

import (
	"io"
	"runtime"
	"sync"
	"sync/atomic"
)

// searchAlone runs f, which may return nil, until count elements are found
func searchAlone(f func() interface{}, count int) []interface{} {
	results := make([]interface{}, count)
	for i := 0; i < len(results); i++ {
		results[i] = nil
		for ; results[i] == nil; results[i] = f() {
		}
	}
	return results
}

// parallelizeAlone calculates the result of f count times
func parallelizeAlone(f func(int) interface{}, count int) []interface{} {
	results := make([]interface{}, count)
	for i := 0; i < len(results); i++ {
		results[i] = f(i)
	}
	return results
}

// command is used to trigger our latent workers to do something.
//
// The idea is that a worker is told to either calculate a function once,
// or keep calculating a function until it returns a non nil result.
type command struct {
	search bool
	// This counter is used to coordinate searching. We want our pool to keep
	// searching until a certain number of successes are found. Each time
	// a new candidate is tried, this counter is checked, to make sure that we
	// need to keep searching. Naturally, we decrement the counter when we produce
	// a success.
	ctr *int64
	// This is the index we evaluate our function at, when not searching
	i int
	f func(int) interface{}
}

// workerSearch is the subroutine called when doing a search command.
//
// We need to keep searching for successful queries of f while *ctr > 0.
// When we find a successful result, we decrement *ctr.
func workerSearch(out chan<- interface{}, f func(int) interface{}, ctr *int64) {
	for atomic.LoadInt64(ctr) > 0 {
		res := f(0)
		if res == nil {
			continue
		}
		newVal := atomic.AddInt64(ctr, -1)
		if newVal < 0 {
			break
		}
		out <- res
	}
}

// worker starts up a new worker, listening to commands, and producing results
func worker(commands <-chan command, out chan<- interface{}) {
	for c := range commands {
		if c.search {
			workerSearch(out, c.f, c.ctr)
		} else {
			out <- c.f(c.i)
		}
	}
}

// Pool represents a pool of workers, used for parallelizing functions.
//
// Function needing a *Pool will work with a nil receiver, doing the equivalent
// work on the current threat instead.
//
// By creating a pool, you avoid the overhead of spinning up goroutines for
// each new operation.
type Pool struct {
	// The common channel used to send commands to the workers.
	//
	// This effectively makes a work stealing pool.
	commands chan command
	// This channel receives in results from the workers
	out chan interface{}
	// This holds the number of workers we've created
	workerCount int
}

// NewPool creates a new pool, with a certain number of workers.
//
// If count <= 0, this will use the number of available CPUs instead.
func NewPool(count int) *Pool {
	var p Pool

	if count <= 0 {
		count = runtime.NumCPU()
	}

	p.commands = make(chan command)
	p.out = make(chan interface{})
	p.workerCount = count

	for i := 0; i < count; i++ {
		go worker(p.commands, p.out)
	}

	return &p
}

// TearDown cleanly tears down a pool, closing channels, etc.
func (p *Pool) TearDown() {
	close(p.commands)
}

// Search queries the function f, until count successes are found.
//
// f is supposed to try a single candidate, returning nil if that candidate isn't
// successful.
//
// The result will be an array containing the first count successes.
func (p *Pool) Search(count int, f func() interface{}) []interface{} {
	if p == nil {
		return searchAlone(f, count)
	}

	results := make([]interface{}, count)

	ctr := int64(count)
	cmd := command{
		search: true,
		ctr:    &ctr,
		f:      func(i int) interface{} { return f() },
	}
	for i := 0; i < p.workerCount; i++ {
		p.commands <- cmd
	}

	for i := 0; i < len(results); i++ {
		results[i] = <-p.out
	}

	return results
}

// Parallelize calls a function count times, passing in indices from 0..count-1.
//
// The result will be a slice containing [f(0), f(1), ..., f(count - 1)].
func (p *Pool) Parallelize(count int, f func(int) interface{}) []interface{} {
	if p == nil {
		return parallelizeAlone(f, count)
	}

	results := make([]interface{}, count)

	for i := 0; i < count; i++ {
		p.commands <- command{
			search: false,
			i:      i,
			f:      f,
		}
	}
	for i := 0; i < len(results); i++ {
		results[i] = <-p.out
	}

	return results
}

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
