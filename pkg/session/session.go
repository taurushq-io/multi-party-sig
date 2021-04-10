package session

import (
	"crypto/rand"
	"sort"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
)

const (
	secParamBytes = 32
	hashLen       = 64
)

// Session contains information related to the current protocol session.
// It simplifies hashing using ssid to various types, and contains the (t,n) parameters
type Session struct {
	// group is a string representing the cryptographic being used
	group string

	selfID uint32
	// parties is a set containing all parties
	parties map[uint32]struct{}
	// sortedParties is a slice with the same contents as parties, but sorted.
	sortedParties []uint32

	// sid is the concatenation of group ∥ threshold ∥ # parties (uint16 be) ∥ party_1 (uint16 be) ∥ ... ∥ party_n (uint16 be)
	// sidHash is 64 bytes SHA3(sid)
	// rid is a 32 byte random ID assigned at the creation of the session.
	sid     []byte
	sidHash [hashLen]byte
	rid     [secParamBytes]byte

	// Hash is the domain separated hash function for this session.
	Hash *hash.Hash

	threshold uint32
}

// New creates a new session for a given group and slice of parties
func New(group string, parties []uint32) (*Session, error) {
	s := &Session{
		group:         group,
		parties:       make(map[uint32]struct{}, len(parties)),
		sortedParties: make([]uint32, 0, len(parties)),
	}

	// remove duplicated
	for _, id := range parties {
		if _, ok := s.parties[id]; !ok {
			s.parties[id] = struct{}{}
			s.sortedParties = append(s.sortedParties, id)
		}
	}

	// sort sortedParties
	sort.Slice(s.sortedParties, func(i, j int) bool {
		return s.sortedParties[i] < s.sortedParties[j]
	})

	// create preimage (group ∥ n ∥ t ∥ p1 ∥ ... ∥ pn )
	n := len(s.parties)
	s.sid = make([]byte, 0, len(s.group)+arith.IDByteSize*(2+n))
	s.sid = append(s.sid, []byte(group)...)
	s.sid = append(s.sid, arith.IDToBytes(uint32(n))...)
	s.sid = append(s.sid, arith.IDToBytes(s.threshold)...)
	for _, id := range s.sortedParties {
		s.sid = append(s.sid, arith.IDToBytes(id)...)
	}

	s.Hash = hash.New(s.sid)

	//// set sidHash
	//sha3.ShakeSum256(s.sidHash[:], s.sid)
	//
	//// Create hash function with initial state of sidHash
	//// This ensures that not too much data is allocated each time we clone the hash.
	//s.hash = sha3.NewCShake256([]byte("CMP"), s.sidHash[:])

	return s, nil
}

// SessionID returns a 32 byte slice which uniquely determines the parties, and the public parameters used.
func (s *Session) SessionID() []byte {
	return s.sid[:secParamBytes]
}

// N returns the number of parties (including those not performing a signing).
func (s *Session) N() uint32 {
	return uint32(len(s.parties))
}

// T returns the threshold of the session. T+1 parties are required to sign/reconstruct the secret key.
func (s *Session) T() uint32 {
	return s.threshold
}

// Includes indicates whether the party is included in the session.
func (s *Session) Includes(id uint32) bool {
	_, ok := s.parties[id]
	return ok
}

// SortedPartySlice returns the original slice of sorted party IDs.
// The returned slice should not be modified.
func (s *Session) SortedPartySlice() []uint32 {
	return s.sortedParties
}

// HashForSelf returns a hash.Hash initialized with this party ID
func (s *Session) HashForSelf() *hash.Hash {
	return s.Hash.CloneWithID(s.selfID)
}

// HashForID returns a hash.Hash initialized with the given party ID
func (s *Session) HashForID(id uint32) *hash.Hash {
	return s.Hash.CloneWithID(id)
}

func (s *Session) UpdateParams(params []byte) error {
	_, err := s.Hash.Write(params)
	return err
}

// RandomSlice returns a random slice {0,1}ˢᵉᶜᵖᵃʳᵃᵐ
func (s *Session) RandomSlice() ([]byte, error) {
	b := make([]byte, secParamBytes)
	_, err := rand.Read(b)
	return b, err
}

// SelfID returns the ID of the party.
func (s *Session) SelfID() uint32 {
	return s.selfID
}
