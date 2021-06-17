package session

import (
	"crypto/ecdsa"
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

// KeygenSession holds all information needed to execute one of the protocols.
// It holds the information called SSID from the protocol and can be thought of as
// SSID = (SID, ...), where SID = (𝔾, q, Gₓ, P₁, ..., Pₙ)
type KeygenSession struct {
	*BaseSession

	// public maps party.ID to party.Public. It contains all public information associated to a party.
	// When keygen has not yet run, all party.Public should contain only the ID
	public map[party.ID]*party.Public

	// secret contains the secret key material ECDSA, Paillier and RID
	secret *party.Secret

	// publicKey is the full ECDSA public key
	publicKey *ecdsa.PublicKey

	// ssid is a cached hash of SSID
	// It corresponds to Hash(G, n, t, P₁, ..., Pₙ, aux_info)
	ssid []byte
}

// NewSession creates a session from given keygen material, and performs full verification.
// If SSID is given, then it checked against the recomputed one.
// No copy of the given data is performed
func NewSession(threshold int, publicInfo map[party.ID]*party.Public, publicKey *ecdsa.PublicKey, secret *party.Secret, SSID []byte) (*KeygenSession, error) {
	parties := make(party.IDSlice, 0, len(publicInfo))
	for id := range publicInfo {
		parties = append(parties, id)
	}

	base, err := NewBaseSession(parties, threshold, secret.ID)
	if err != nil {
		return nil, err
	}

	s := &KeygenSession{
		BaseSession: base,
		public:      publicInfo,
		secret:      secret,
		publicKey:   publicKey,
		ssid:        SSID,
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

func (s KeygenSession) Public(id party.ID) *party.Public {
	return s.public[id]
}

func (s KeygenSession) Secret() *party.Secret {
	return s.secret
}

func (s KeygenSession) PublicKey() *ecdsa.PublicKey {
	return s.publicKey
}

// SSID returns the hash of the SSID
func (s KeygenSession) SSID() []byte {
	return s.ssid
}

// Validate checks all the parameters and returns an error if an inconsistency was detected.
// Makes sure of the following:
//   - Public info and Secret are compatible
//   - SSID is computed correctly and is the same for all Public data
//   - PublicKey corresponds to the Lagrange interpolation of the Public ECDSA shares
//   - Paillier and Pedersen parameters are good.
func (s KeygenSession) Validate() error {
	if s.secret == nil {
		return errors.New("session: secret cannot be nil")
	}
	if len(s.secret.RID) != params.SecBytes {
		return errors.New("session: secret must contain RID")
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
// - Hash(𝔾, q, G_x, t, n, P₁, ..., Pₙ, {(Nⱼ, Sⱼ, Tⱼ)}ⱼ}
func (s KeygenSession) Hash() *hash.Hash {
	h := s.BaseSession.Hash()

	// RID (since secret is already set)
	_, _ = h.Write(s.secret.RID)

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
func (s KeygenSession) Clone() Session {
	public2 := make(map[party.ID]*party.Public, len(s.public))
	for j, publicJ := range s.public {
		public2[j] = publicJ.Clone()
	}

	s2 := &KeygenSession{
		BaseSession: s.BaseSession.Clone().(*BaseSession),
		public:      public2,
		secret:      s.secret.Clone(),
		publicKey:   &(*s.publicKey),
		ssid:        computeSSID(s),
	}
	return s2
}

// computePublicKey returns an ecdsa.PublicKey computed via Lagrange interpolation
// of all public shares.
func (s KeygenSession) computePublicKey() *ecdsa.PublicKey {
	sum := curve.NewIdentityPoint()
	tmp := curve.NewIdentityPoint()
	for partyID, partyJ := range s.public {
		lagrange := s.PartyIDs().Lagrange(partyID)
		tmp.ScalarMult(lagrange, partyJ.ECDSA)
		sum.Add(sum, tmp)
	}
	return sum.ToPublicKey()
}
