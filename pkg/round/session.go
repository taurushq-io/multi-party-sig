package round

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

var (
	ErrSelfIDNotIncluded = errors.New("list of Party.ID does not contain self ID")
)

// Session contains information related to the current protocol session.
// It simplifies hashing using ssid to various types, and contains the (t,n) parameters
type Session struct {
	// group for signature
	group elliptic.Curve

	// Parties is the full list of party's IDs
	Parties party.IDSlice

	// Threshold is the integer t which defines the maximum number of corruptions tolerated for this session.
	Threshold int

	// Public maps party.ID to party.Public. It contains all public information associated to a party.
	// When keygen has not yet run, all party.Public should contain only the ID and SSID
	Public map[party.ID]*party.Public

	// Secret contains the
	Secret *party.Secret

	PublicKey *ecdsa.PublicKey

	// SSID returns the hash of the SSID
	// It corresponds to H(G, n, t, P₁, ..., Pₙ, aux_info)
	ssid []byte
}

// NewSession creates a session from stored keygen material. It performs no copy of the initial
func NewSession(publicKey ecdsa.PublicKey, SSID []byte, threshold int, publicInfo map[party.ID]*party.Public, secret *party.Secret) (*Session, error) {
	n := len(publicInfo)

	parties := make(party.IDSlice, 0, n)
	for id := range publicInfo {
		parties = append(parties, id)
	}
	parties.Sort()

	s := &Session{
		group:     publicKey.Curve,
		Parties:   parties,
		Threshold: threshold,
		Public:    publicInfo,
		Secret:    secret,
		PublicKey: &publicKey,
		ssid:      SSID,
	}

	// Check that all public info have right information
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// NewSessionKeygen returns a new Session where the fields without any Keygen material.
// It only sets:
//   - ID for all parties from partyIDs (making sure there are no duplicates and it includes selfID)
//   - SSID which is the hash of the SID = (G, P₁, ..., Pₙ
func NewSessionKeygen(selfID party.ID, group elliptic.Curve, partyIDs party.IDSlice, threshold int) (*Session, error) {
	var err error
	n := len(partyIDs)

	parties := make(party.IDSlice, n)
	copy(parties, partyIDs)
	parties.Sort()

	s := &Session{
		group:     group,
		Parties:   parties,
		Threshold: threshold,
	}

	// get ssid hash
	s.ssid, err = s.RecomputeSSID()
	if err != nil {
		return nil, fmt.Errorf("session.NewSessionKeygen: failed to get hash of SID: %w", err)
	}

	// Create empty public info map
	s.Public = make(map[party.ID]*party.Public, n)
	for _, id := range parties {
		s.Public[id] = &party.Public{
			ID:   id,
			SSID: s.ssid,
		}
	}

	// initialize secret
	s.Secret = &party.Secret{ID: selfID}

	if err = s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// RecomputeSSID regenerates the hash of the SSID
func (s *Session) RecomputeSSID() ([]byte, error) {
	// initialize hash function with sid information
	hSID, err := s.Hash()
	if err != nil {
		return nil, fmt.Errorf("session: failed to initialize hash function with SID: %w", err)
	}
	// get ssid hash
	ssid, err := hSID.ReadBytes(make([]byte, params.HashBytes))
	if err != nil {
		return nil, fmt.Errorf("session: failed to get hash of SID: %w", err)
	}
	return ssid, nil
}

// KeygenDone checks if the secret is set. If so, then we assume we are in a post-keygen state.
// This does not perform any other validation on the state of the public party info.
// You should run Session.Validate() for that.
func (s Session) KeygenDone() bool {
	return s.Secret != nil && len(s.Secret.RID) != 0 && s.Secret.ECDSA != nil && s.Secret.Paillier != nil
}

// N returns the total number of parties in this session. This is the N of a TSS.
func (s Session) N() int {
	return len(s.Parties)
}

// Validate checks all the parameters and returns an error if an inconsistency was detected.
// Makes sure of the following:
//   - Public info and Secret are compatible
//   - SSID is computed correctly and is the same for all Public data
//   - PublicKey corresponds to the Lagrange interpolation of the Public ECDSA shares
//   - Paillier and Pedersen parameters are good.
func (s Session) Validate() error {
	// group
	if s.group == nil {
		return errors.New("session: group is nil")
	}

	// check the list of parties is sorted
	if !s.Parties.Sorted() {
		return errors.New("session: party list was not sorted")
	}

	// check that the list of parties corresponds with the map of party.Public
	if len(s.Parties) != len(s.Public) {
		return errors.New("session: Parties and Public length mismatch")
	}

	// verify our ID is present
	if !s.Parties.Contains(s.Secret.ID) {
		return fmt.Errorf("session: selfID: %s, err: %w", s.Secret.ID, ErrSelfIDNotIncluded)
	}

	// check threshold ∈ [1, n-1]
	n := len(s.Parties)
	if s.Threshold < 1 || s.Threshold >= n {
		return fmt.Errorf("session: threshold setting (%d,%d) invalid", s.Threshold, n)
	}

	// check non nil
	if s.Secret == nil ||
		len(s.Parties) == 0 ||
		len(s.Public) == 0 ||
		len(s.ssid) != params.HashBytes {
		return errors.New("session: some parameters were nil")
	}

	// validate secret
	publicI, ok := s.Public[s.Secret.ID]
	if !ok {
		return errors.New("session: Secret does not have a corresponding Public")
	}

	// do a full validation of secret if keygen is done
	if err := s.Secret.ValidatePublic(publicI); err != nil {
		return fmt.Errorf("session: secret data: %w", err)
	}

	keygenDone := s.KeygenDone()
	// basic check for each party
	for _, j := range s.Parties {
		publicJ, ok := s.Public[j]
		if !ok {
			return fmt.Errorf("session: party %s not included in Public", j)
		}
		if j != publicJ.ID {
			return fmt.Errorf("session: party %s: ID mismatch", j)
		}
		if !bytes.Equal(publicJ.SSID, s.ssid) {
			return fmt.Errorf("session: party %s: SSID mismatch", j)
		}

		// do a full validation of publicJ if keygen is done
		if publicJ.KeygenDone() != keygenDone {
			return fmt.Errorf("session: party %s: no keygen data", j)
		}
		// validate public
		if err := publicJ.Validate(); err != nil {
			return fmt.Errorf("session: party %s: %w", j, err)
		}

	}

	// check ssid again
	ssid, err := s.RecomputeSSID()
	if err != nil {
		return fmt.Errorf("session: failed to generate ssid: %w", err)
	}
	if !bytes.Equal(ssid, s.ssid) {
		return errors.New("session: ssid mismatch")
	}

	newKey, err := s.ComputePublicKey()
	if err != nil {
		return err
	}
	if !s.PublicKey.Equal(newKey) {
		return errors.New("session: public key mismatch")
	}

	return nil
}

// Hash returns a new hash.Hash function initialized with the full SSID.
// It assumes that the state is in a correct, and can panic if it is not.
// Calling hash.Sum() on the resulting hash function returns the hash of the SSID.
func (s *Session) Hash() (*hash.Hash, error) {
	var err error
	intBuffer := make([]byte, 8)

	h := hash.New()

	// Write group information
	if _, err = h.Write([]byte(s.group.Params().Name)); err != nil {
		return nil, fmt.Errorf("session.Hash: write group: %w", err)
	} // 𝔾
	if _, err = h.Write(s.group.Params().N.Bytes()); err != nil {
		return nil, fmt.Errorf("session.Hash: write q: %w", err)
	} // q
	if _, err = h.Write(s.group.Params().Gx.Bytes()); err != nil {
		return nil, fmt.Errorf("session.Hash: write gx: %w", err)
	} // gₓ

	// write n
	binary.BigEndian.PutUint64(intBuffer, uint64(len(s.Parties)))
	if _, err = h.Write(intBuffer); err != nil {
		return nil, fmt.Errorf("session.Hash: write n: %w", err)
	}

	// write t
	binary.BigEndian.PutUint64(intBuffer, uint64(s.Threshold))
	if _, err = h.Write(intBuffer); err != nil {
		return nil, fmt.Errorf("session.Hash: write t: %w", err)
	}

	// write P₁, ..., Pₙ
	for _, partyID := range s.Parties {
		if _, err = h.Write([]byte(partyID)); err != nil {
			return nil, fmt.Errorf("session.Hash: write party %s: %w", partyID, err)
		}
	}

	// stop here if we are in the keygen phase.
	if !s.KeygenDone() {
		return h, nil
	}

	// RID (since secret is already set)
	if _, err = h.Write(s.Secret.RID); err != nil {
		return nil, fmt.Errorf("session.Hash: write RID: %w", err)
	}

	// write all public info from parties in order
	for _, partyID := range s.Parties {
		partyI := s.Public[partyID]

		// Write ECDSA public key
		if _, err = h.Write(partyI.ECDSA.Bytes()); err != nil {
			return nil, fmt.Errorf("session.Hash: party %s, write ECDSA: %w", partyID, err)
		}

		// write N,S,T
		// we don't write the paillier key since it is assumed to be the same as the N from the Pedersen parameters.
		if err = h.WriteAny(partyI.Pedersen); err != nil {
			return nil, fmt.Errorf("session.Hash: party %s, write Pedersen: %w", partyID, err)
		}
	}

	return h, nil
}

// ComputePublicKey returns an ecdsa.PublicKey computed via Lagrange interpolation
// of all public shares.
func (s *Session) ComputePublicKey() (*ecdsa.PublicKey, error) {
	sum := curve.NewIdentityPoint()
	tmp := curve.NewIdentityPoint()
	for partyID, partyJ := range s.Public {
		lagrange := s.Parties.Lagrange(partyID)
		tmp.ScalarMult(lagrange, partyJ.ECDSA)
		sum.Add(sum, tmp)
	}
	return sum.ToPublicKey(), nil
}

// Clone performs a deep copy of a all fields. In particular, it copies all public party data
// as well as the secret.
func (s *Session) Clone() *Session {
	public2 := make(map[party.ID]*party.Public, len(s.Public))
	for j, publicJ := range s.Public {
		public2[j] = publicJ.Clone()
	}

	s2 := &Session{
		group:     s.group,
		Parties:   s.Parties.Copy(),
		Threshold: s.Threshold,
		Public:    public2,
		Secret:    s.Secret.Clone(),
		PublicKey: &(*s.PublicKey),
		ssid:      append([]byte{}, s.ssid...),
	}
	return s2
}

// SelfID returns the ID of the party we have the secrets for
func (s Session) SelfID() party.ID {
	return s.Secret.ID
}

// SetSSID overwrites the session SSID hash and sets it for all public info of parties.
// No check is performed, so you should probably run Session.Validate() to make sure it is correct.
func (s *Session) SetSSID(ssid []byte) {
	s.ssid = ssid
	for _, p := range s.Public {
		p.SSID = ssid
	}
}
