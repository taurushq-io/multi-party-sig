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

// Keygen is a Session which represents the state where a keygen can be performed.
// The information it contains can be seen as the "sid" part of the SSID.
type Keygen struct {
	// group for signature
	group elliptic.Curve

	// PartyIDs is the full list of party's IDs
	partyIDs party.IDSlice

	// threshold is the integer t which defines the maximum number of corruptions tolerated for this session.
	threshold int

	sid []byte

	selfID party.ID
}

// NewKeygenSession returns an empty session where no key material is set. It can be used in the refresh protocol
// to establish a new public key.
func NewKeygenSession(partyIDs []party.ID, threshold int, selfID party.ID) (*Keygen, error) {
	var err error
	ids := make(party.IDSlice, len(partyIDs))
	copy(ids, partyIDs)
	ids.Sort()
	s := &Keygen{
		group:     secp256k1.S256(), // todo change to allow different groups
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

// Curve returns the curve over which this session is defined.
func (s Keygen) Curve() elliptic.Curve {
	return s.group
}

// Threshold returns the maximum number of corruption tolerated, i.e. Threshold() + 1 is the minimum number
// of party's shares required to reconstruct the secret/sign a message.
func (s Keygen) Threshold() int {
	return s.threshold
}

// PartyIDs returns the a sorted slice of all the parties in this session
func (s Keygen) PartyIDs() party.IDSlice {
	return s.partyIDs
}

// N is the total number of parties in this session.
func (s Keygen) N() int {
	return len(s.partyIDs)
}

// Public returns a new party.Public struct initialized with the ID only.
func (s Keygen) Public(id party.ID) *party.Public {
	if s.partyIDs.Contains(id) {
		return &party.Public{
			ID: id,
		}
	}
	return nil
}

// RID returns an empty 32 byte string since it has not been set yet
func (s Keygen) RID() []byte {
	return make([]byte, params.SecBytes)
}

// SSID returns the hash of the SID
func (s Keygen) SSID() []byte {
	if len(s.sid) == 0 {
		s.sid = computeSSID(s)
	}
	return s.sid
}

// Secret returns a new party.Secret initialized with the ID only
func (s Keygen) Secret() *party.Secret {
	return &party.Secret{
		ID: s.selfID,
	}
}

// SelfID is the ID of this party
func (s Keygen) SelfID() party.ID {
	return s.selfID
}

// SelfIndex returns the index of the party in PartyIDs that we have the secrets for, in the list of parties in the protocol.
// If we are in a Sign session we return the index in SignerIDs.
func (s Keygen) SelfIndex() int {
	return s.partyIDs.GetIndex(s.selfID)
}

// PublicKey returns nil since no key material has been generated
func (s Keygen) PublicKey() *ecdsa.PublicKey {
	return nil
}

// Hash returns a new hash.Hash function initialized with the full SSID.
// It assumes that the state is in a correct, and can panic if it is not.
// Calling hash.Sum() on the resulting hash function returns the hash of the SSID.
// It computes
// - Hash(𝔾, q, G_x, t, n, P₁, …, Pₙ,}
func (s Keygen) Hash() *hash.Hash {
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

func (s Keygen) Clone() Session {
	sid2 := make([]byte, params.SizeSSID)
	copy(sid2, s.sid)

	return &Keygen{
		group:     s.group,
		partyIDs:  s.partyIDs.Copy(),
		threshold: s.threshold,
		sid:       sid2,
		selfID:    s.selfID,
	}
}

// Validate performs basic checks to verify that all the party ID's are correct
func (s Keygen) Validate() error {
	return validate(s)
}

func (s Keygen) computePublicKey() *ecdsa.PublicKey {
	return nil
}
