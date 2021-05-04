package hash

import (
	"bytes"
	"crypto/rand"

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
	commitment := make([]byte, params.HashBytes)

	if _, err = rand.Read(decommitment); err != nil {
		return nil, nil, err
	}

	h := hash.CloneWithID(id)

	for _, item := range data {
		if err = h.WriteAny(item); err != nil {
			return nil, nil, err
		}
	}

	if err = h.WriteBytes(decommitment); err != nil {
		return nil, nil, err
	}

	if _, err = h.ReadBytes(commitment); err != nil {
		return nil, nil, err
	}

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
		if err = h.WriteAny(item); err != nil {
			return false
		}
	}

	if err = h.WriteBytes(d); err != nil {
		return false
	}

	computedCommitment := make([]byte, params.HashBytes)
	if _, err = h.ReadBytes(computedCommitment); err != nil {
		return false
	}

	return bytes.Equal(computedCommitment, c)
}
