package session

import (
	"bytes"
	"crypto/rand"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

// Session contains information related to the current protocol session.
// It simplifies hashing using ssid to various types, and contains the (t,n) parameters
type Session struct {
	selfID uint32

	partySet map[uint32]bool

	// hash is the domain separated hash function for this session.
	hash *hash.Hash

	ssid []byte
}

// New creates a new session for a given group and slice of parties
func New(config *BaseConfig) (*Session, error) {
	ssid := config.SSID()
	s := &Session{
		selfID:   config.SelfID(),
		hash:     hash.New(ssid),
		partySet: make(map[uint32]bool, config.N()),
		ssid:     ssid,
	}

	for _, id := range config.Parties() {
		s.partySet[id] = true
	}

	return s, nil
}

// ValidParty returns true if the party ID belongs to one of the participants
func (s Session) ValidParty(id uint32) bool {
	return s.partySet[id]
}

// ValidSSID returns true if the SSID is the one for this session
func (s Session) ValidSSID(ssid []byte) bool {
	return len(ssid) == len(s.ssid) && bytes.Equal(ssid, s.ssid)
}

// UpdateParams updates the state of the hash function used for this session.
func (s *Session) UpdateParams(params []byte) error {
	_, err := s.hash.Write(params)
	return err
}

// HashForSelf returns a hash.Hash initialized with this party ID
func (s *Session) HashForSelf() *hash.Hash {
	return s.hash.CloneWithID(s.selfID)
}

// HashForID returns a hash.Hash initialized with the given party ID
func (s *Session) HashForID(id uint32) *hash.Hash {
	return s.hash.CloneWithID(id)
}

// Commit creates a commitment to data, and returns a commitment hash, and a decommitment string such that
// commitment = h(id, data, decommitment)
func (s *Session) Commit(id uint32, data ...interface{}) (commitment, decommitment []byte, err error) {
	decommitment = make([]byte, params.SecBytes)
	commitment = make([]byte, params.HashBytes)

	if _, err = rand.Read(decommitment); err != nil {
		return nil, nil, err
	}

	h := s.HashForID(id)

	for _, d := range data {
		if err = h.WriteAny(d); err != nil {
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
func (s *Session) Decommit(id uint32, commitment, decommitment []byte, data ...interface{}) bool {
	var err error
	if len(commitment) != params.HashBytes || len(decommitment) != params.SecBytes {
		return false
	}

	h := s.HashForID(id)
	for _, d := range data {
		if err = h.WriteAny(d); err != nil {
			return false
		}
	}

	if err = h.WriteBytes(decommitment); err != nil {
		return false
	}

	computedCommitment := make([]byte, params.HashBytes)
	if _, err = h.ReadBytes(computedCommitment); err != nil {
		return false
	}

	return bytes.Equal(computedCommitment, commitment)
}
