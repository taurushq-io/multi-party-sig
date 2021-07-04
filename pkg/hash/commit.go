package hash

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

type (
	Commitment   []byte
	Decommitment []byte
)

// Commit creates a commitment to data, and returns a commitment hash, and a decommitment string such that
// commitment = h(id, data, decommitment)
func (hash *Hash) Commit(id party.ID, data ...interface{}) (Commitment, Decommitment, error) {
	var err error
	decommitment := make([]byte, params.SecBytes)

	if _, err = rand.Read(decommitment); err != nil {
		return nil, nil, fmt.Errorf("hash.Commit: failed to generate decommitment: %w", err)
	}

	h := hash.CloneWithID(id)

	for _, item := range data {
		if _, err = h.WriteAny(item); err != nil {
			return nil, nil, fmt.Errorf("hash.Commit: failed to write data: %w", err)
		}
	}

	_, _ = h.Write(decommitment)

	commitment, _ := h.ReadBytes(nil)

	return commitment, decommitment, nil
}

// Decommit verifies that the commitment corresponds to the data and decommitment such that
// commitment = h(id, data, decommitment)
func (hash *Hash) Decommit(id party.ID, c Commitment, d Decommitment, data ...interface{}) bool {
	var err error
	if len(c) != params.HashBytes || len(d) != params.SecBytes {
		return false
	}

	h := hash.CloneWithID(id)

	for _, item := range data {
		if _, err = h.WriteAny(item); err != nil {
			return false
		}
	}

	_, _ = h.Write(d)

	computedCommitment, _ := h.ReadBytes(nil)

	return bytes.Equal(computedCommitment, c)
}
