package session

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

type BaseSession struct {
	// group for signature
	group elliptic.Curve

	// PartyIDs is the full list of party's IDs
	partyIDs party.IDSlice

	// threshold is the integer t which defines the maximum number of corruptions tolerated for this session.
	threshold int

	sid []byte

	selfID party.ID
}

// todo add group
func NewBaseSession(partyIDs []party.ID, threshold int, selfID party.ID) (*BaseSession, error) {
	var err error
	ids := make(party.IDSlice, len(partyIDs))
	copy(ids, partyIDs)
	ids.Sort()
	s := &BaseSession{
		group:     secp256k1.S256(),
		partyIDs:  ids,
		threshold: threshold,
		sid:       nil,
		selfID:    selfID,
	}

	// get SSID hash
	s.sid = computeSSID(s)

	// perform validation
	if err = s.Validate(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s BaseSession) Curve() elliptic.Curve {
	return s.group
}

func (s BaseSession) Threshold() int {
	return s.threshold
}

func (s BaseSession) PartyIDs() party.IDSlice {
	return s.partyIDs
}

func (s BaseSession) N() int {
	return len(s.partyIDs)
}

// Public returns a new party.Public struct initialized with the ID only.
func (s BaseSession) Public(id party.ID) *party.Public {
	if s.partyIDs.Contains(id) {
		return &party.Public{
			ID: id,
		}
	}
	return nil
}

// SSID returns the hash of the SID
func (s BaseSession) SSID() []byte {
	if len(s.sid) == 0 {
		s.sid = computeSSID(s)
	}
	return s.sid
}

// Secret returns a new party.Secret initialized with the ID only
func (s BaseSession) Secret() *party.Secret {
	return &party.Secret{
		ID: s.selfID,
	}
}

func (s BaseSession) SelfID() party.ID {
	return s.selfID
}

// SelfIndex returns the index of the party in PartyIDs that we have the secrets for, in the list of parties in the protocol.
// If we are in a Sign session we return the index in SignerIDs.
func (s BaseSession) SelfIndex() int {
	return s.partyIDs.GetIndex(s.selfID)
}

// PublicKey returns nil since no key material has been generated
func (s BaseSession) PublicKey() *ecdsa.PublicKey {
	return nil
}

// Hash returns a new hash.Hash function initialized with the full SSID.
// It assumes that the state is in a correct, and can panic if it is not.
// Calling hash.Sum() on the resulting hash function returns the hash of the SSID.
// It computes
// - Hash(𝔾, q, G_x, t, n, P₁, ..., Pₙ,}
func (s BaseSession) Hash() *hash.Hash {
	intBuffer := make([]byte, 8)

	h := hash.New()

	// Write group information
	_, _ = h.Write([]byte(s.group.Params().Name)) // 𝔾
	_, _ = h.Write(s.group.Params().N.Bytes())    // q
	_, _ = h.Write(s.group.Params().Gx.Bytes())   // Gₓ

	// write t
	binary.BigEndian.PutUint64(intBuffer, uint64(s.threshold))

	// write PartyIDs (with n)
	_, _ = h.WriteAny(s.partyIDs)

	return h
}

func (s BaseSession) Clone() Session {
	sid2 := make([]byte, params.SizeSSID)
	copy(sid2, s.sid)

	return &BaseSession{
		group:     s.group,
		partyIDs:  s.partyIDs.Copy(),
		threshold: s.threshold,
		sid:       sid2,
		selfID:    s.selfID,
	}
}

func (s BaseSession) Validate() error {
	return validate(s)
}

func (s BaseSession) computePublicKey() *ecdsa.PublicKey {
	return nil
}
