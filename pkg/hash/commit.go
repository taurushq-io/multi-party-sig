package hash

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

type (
	Commitment   []byte
	Decommitment []byte
)

// WriteTo implements the io.WriterTo interface for Commitment.
func (c Commitment) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(c)
	return int64(n), err
}

// Domain implements WriterToWithDomain, and separates this type within hash.Hash.
func (Commitment) Domain() string {
	return "Commitment"
}

// WriteTo implements the io.WriterTo interface for Decommitment.
func (d Decommitment) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(d)
	return int64(n), err
}

// Domain implements WriterToWithDomain, and separates this type within hash.Hash.
func (Decommitment) Domain() string {
	return "Decommitment"
}

// Commit creates a commitment to data, and returns a commitment hash, and a decommitment string such that
// commitment = h(data, decommitment)
func (hash *Hash) Commit(data ...interface{}) (Commitment, Decommitment, error) {
	var err error
	decommitment := Decommitment(make([]byte, params.SecBytes))

	if _, err = rand.Read(decommitment); err != nil {
		return nil, nil, fmt.Errorf("hash.Commit: failed to generate decommitment: %w", err)
	}

	h := hash.Clone()

	for _, item := range data {
		if _, err = h.WriteAny(item); err != nil {
			return nil, nil, fmt.Errorf("hash.Commit: failed to write data: %w", err)
		}
	}

	_, _ = h.WriteAny(decommitment)

	commitment := h.ReadBytes(nil)

	return commitment, decommitment, nil
}

// Decommit verifies that the commitment corresponds to the data and decommitment such that
// commitment = h(data, decommitment)
func (hash *Hash) Decommit(c Commitment, d Decommitment, data ...interface{}) bool {
	var err error
	if len(c) != params.HashBytes || len(d) != params.SecBytes {
		return false
	}

	h := hash.Clone()

	for _, item := range data {
		if _, err = h.WriteAny(item); err != nil {
			return false
		}
	}

	_, _ = h.WriteAny(d)

	computedCommitment := h.ReadBytes(nil)

	return bytes.Equal(computedCommitment, c)
}
