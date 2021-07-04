package session

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

// Refresh is a Session where the parties have jointly generated the necessary key material.
// In particular, this is the only struct that is Marshallable since it must be stored once created.
type Refresh struct {
	*Keygen

	// public maps party.ID to party.Public. It contains all public information associated to a party.
	// When keygen has not yet run, all party.Public should contain only the ID
	public map[party.ID]*party.Public

	// secret contains the secret key material ECDSA, Paillier and RID
	secret *party.Secret

	// publicKey is the full ECDSA public key
	publicKey *ecdsa.PublicKey

	// rid is a 32 byte random identifier generated for this session
	rid []byte

	// ssid is a cached hash of SSID
	// It corresponds to Hash(G, n, t, P₁, …, Pₙ, aux_info)
	ssid []byte
}

// NewRefreshSession creates a session from given keygen material, and performs full verification.
// If SSID is given, then it checked against the recomputed one.
// No copy of the given data is performed
func NewRefreshSession(threshold int, publicInfo map[party.ID]*party.Public, RID []byte, publicKey *ecdsa.PublicKey, secret *party.Secret, SSID []byte) (*Refresh, error) {
	parties := make(party.IDSlice, 0, len(publicInfo))
	for id := range publicInfo {
		parties = append(parties, id)
	}

	base, err := NewKeygenSession(parties, threshold, secret.ID)
	if err != nil {
		return nil, err
	}

	rid := make([]byte, params.SecBytes)
	copy(rid, RID)

	s := &Refresh{
		Keygen:    base,
		public:    publicInfo,
		secret:    secret,
		publicKey: publicKey,
		rid:       rid,
		ssid:      SSID,
	}
	if s.ssid == nil {
		s.ssid = computeSSID(s)
	}

	// Check that all public info have right information
	if err = s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Public returns the public key material we have stored for the party with the given id.
func (s Refresh) Public(id party.ID) *party.Public {
	return s.public[id]
}

// Secret returns the stored secret key material.
func (s Refresh) Secret() *party.Secret {
	return s.secret
}

// PublicKey returns the group's public ECDSA key
func (s Refresh) PublicKey() *ecdsa.PublicKey {
	return s.publicKey
}

// RID is the random 32 byte identifier generated during keygen
func (s Refresh) RID() []byte {
	return s.rid
}

// SSID returns the hash of the SSID
func (s Refresh) SSID() []byte {
	return s.ssid
}

// Validate checks all the parameters and returns an error if an inconsistency was detected.
// Makes sure of the following:
//   - Public info and Secret are compatible
//   - SSID is computed correctly and is the same for all Public data
//   - PublicKey corresponds to the Lagrange interpolation of the Public ECDSA shares
//   - Paillier and Pedersen parameters are good.
func (s Refresh) Validate() error {
	if s.secret == nil {
		return errors.New("session: secret cannot be nil")
	}

	if s.secret.ECDSA == nil || s.secret.Paillier == nil {
		return errors.New("session: secret must contain ECDSA and Paillier secrets")
	}

	// check that the list of parties corresponds with the map of party.Public
	if len(s.public) != s.N() {
		return errors.New("session: PartyIDs and Public length mismatch")
	}

	return validate(s)
}

// Hash returns a new hash.Hash function initialized with the full SSID.
// It assumes that the state is in a correct, and can panic if it is not.
// Calling hash.Sum() on the resulting hash function returns the hash of the SSID.
// It computes
// - Hash(𝔾, q, G_x, t, n, P₁, …, Pₙ, {(Nⱼ, Sⱼ, Tⱼ)}ⱼ}
func (s Refresh) Hash() *hash.Hash {
	h := s.Keygen.Hash()

	// RID (since secret is already set)
	_, _ = h.Write(s.rid)

	// write all public info from parties in order
	for _, partyID := range s.PartyIDs() {
		partyI := s.public[partyID]

		// Write ECDSA public key
		_, _ = h.WriteAny(partyI.ECDSA)

		// write N,S,T
		// we don't write the paillier key since it is assumed to be the same as the N from the Pedersen parameters.
		_, _ = h.WriteAny(partyI.Pedersen)
	}

	return h
}

// Clone performs a deep copy of a all fields. In particular, it copies all public party data
// as well as the secret.
func (s Refresh) Clone() Session {
	public2 := make(map[party.ID]*party.Public, len(s.public))
	for j, publicJ := range s.public {
		public2[j] = publicJ.Clone()
	}

	s2 := &Refresh{
		Keygen:    s.Keygen.Clone().(*Keygen),
		public:    public2,
		secret:    s.secret.Clone(),
		publicKey: &(*s.publicKey),
		rid:       append([]byte{}, s.rid...),
		ssid:      computeSSID(s),
	}
	return s2
}

// computePublicKey returns an ecdsa.PublicKey computed via Lagrange interpolation
// of all public shares.
func (s Refresh) computePublicKey() *ecdsa.PublicKey {
	sum := curve.NewIdentityPoint()
	tmp := curve.NewIdentityPoint()
	for partyID, partyJ := range s.public {
		lagrange := s.PartyIDs().Lagrange(partyID)
		tmp.ScalarMult(lagrange, partyJ.ECDSA)
		sum.Add(sum, tmp)
	}
	return sum.ToPublicKey()
}

var _ json.Marshaler = (*Refresh)(nil)
var _ json.Unmarshaler = (*Refresh)(nil)

type jsonSession struct {
	// TODO include Group information
	//Group string `json:"group"`
	PublicKey *curve.Point    `json:"public_key"`
	RID       []byte          `json:"rid"`
	SSID      []byte          `json:"ssid"`
	Threshold int             `json:"threshold"`
	Secret    *party.Secret   `json:"secret"`
	Public    []*party.Public `json:"public"`
}

func (s Refresh) MarshalJSON() ([]byte, error) {
	public := make([]*party.Public, 0, s.N())
	for _, id := range s.PartyIDs() {
		public = append(public, s.Public(id))
	}
	x := jsonSession{
		PublicKey: curve.FromPublicKey(s.PublicKey()),
		RID:       s.RID(),
		SSID:      s.SSID(),
		Threshold: s.Threshold(),
		Secret:    s.Secret(),
		Public:    public,
	}
	return json.Marshal(x)
}

func (s *Refresh) UnmarshalJSON(bytes []byte) error {
	var x jsonSession
	err := json.Unmarshal(bytes, &x)
	if err != nil {
		return err
	}

	n := len(x.Public)
	public := make(map[party.ID]*party.Public, n)
	partyIDs := make(party.IDSlice, 0, n)
	for _, partyJ := range x.Public {
		partyIDs = append(partyIDs, partyJ.ID)
		public[partyJ.ID] = partyJ
	}
	partyIDs.Sort()

	s2, err := NewRefreshSession(x.Threshold, public, x.RID, x.PublicKey.ToPublicKey(), x.Secret, x.SSID)
	if err != nil {
		return err
	}
	*s = *s2
	return nil
}
