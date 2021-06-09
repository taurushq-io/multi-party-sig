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

// Session holds all information needed to execute one of the protocols.
// It holds the information called SSID from the protocol and can be thought of as
// SSID = (SID, ...), where SID = (𝔾, q, Gₓ, P₁, ..., Pₙ)
//
//
type Session struct {
	// group for signature
	group elliptic.Curve

	// PartyIDs is the full list of party's IDs
	PartyIDs party.IDSlice

	// Threshold is the integer t which defines the maximum number of corruptions tolerated for this session.
	Threshold int

	// Public maps party.ID to party.Public. It contains all public information associated to a party.
	// When keygen has not yet run, all party.Public should contain only the ID and SSID
	Public map[party.ID]*party.Public

	// Secret contains the secret key material ECDSA, Paillier and RID
	Secret *party.Secret

	// PublicKey is the full ECDSA public key
	PublicKey *ecdsa.PublicKey

	// ssid is a cached hash of SSID
	// It corresponds to H(G, n, t, P₁, ..., Pₙ, aux_info)
	ssid []byte

	// SignerIDs is a subset of PartyIDs which are signing a message
	SignerIDs party.IDSlice

	// SigningParties is a copy of the Public for all parties in SignerIDs
	SigningParties map[party.ID]*party.Public

	// Message is the message to be signed.
	Message []byte
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
		PartyIDs:  parties,
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
		PartyIDs:  parties,
		Threshold: threshold,
	}

	// get SSID hash
	s.ssid, err = s.computeSSID()
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

func (s Session) computeSSID() ([]byte, error) {
	// initialize hash function with sid information
	hSID, err := s.Hash()
	if err != nil {
		return nil, fmt.Errorf("session: failed to initialize hash function with SID: %w", err)
	}
	// get SSID hash
	ssid, err := hSID.ReadBytes(make([]byte, params.HashBytes))
	if err != nil {
		return nil, fmt.Errorf("session: failed to get hash of SID: %w", err)
	}
	return ssid, nil
}

// SSID returns the hash of the SSID
func (s Session) SSID() []byte {
	return s.ssid
}

// RecomputeSSID sets the SSID for all parties
func (s *Session) RecomputeSSID() error {
	ssid, err := s.computeSSID()
	if err != nil {
		return err
	}
	s.ssid = ssid
	for _, p := range s.Public {
		p.SSID = ssid
	}
	if s.IsSigning() {
		for _, p := range s.SigningParties {
			p.SSID = ssid
		}
	}
	return nil
}

// KeygenDone checks if the secret is set. If so, then we assume we are in a post-keygen state.
// This does not perform any other validation on the state of the public party info.
// You should run Session.Validate() for that.
func (s Session) KeygenDone() bool {
	return s.Secret != nil && len(s.Secret.RID) != 0 && s.Secret.ECDSA != nil && s.Secret.Paillier != nil
}

// N returns the total number of parties in this session. This is the N of a TSS.
func (s Session) N() int {
	return len(s.PartyIDs)
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

	// check threshold ∈ [1, n-1]
	n := len(s.PartyIDs)
	if s.Threshold < 1 || s.Threshold >= n {
		return fmt.Errorf("session: threshold setting (%d,%d) invalid", s.Threshold, n)
	}

	// check if secret is nil
	if s.Secret == nil {
		return errors.New("session: Secret is not yet set")
	}

	// check SSID length
	if len(s.ssid) != params.HashBytes {
		return errors.New("session: SSID has wrong length")
	}

	// check PartyIDs
	if len(s.PartyIDs) == 0 {
		return errors.New("session: PartyIDs is empty")
	}

	// check the list of parties is sorted
	if !s.PartyIDs.Sorted() {
		return errors.New("session: party list was not sorted")
	}

	// check that the list of parties corresponds with the map of party.Public
	if len(s.PartyIDs) != len(s.Public) {
		return errors.New("session: PartyIDs and Public length mismatch")
	}

	// verify our ID is present
	if !s.PartyIDs.Contains(s.SelfID()) {
		return fmt.Errorf("session: selfID: %s, err: %w", s.Secret.ID, ErrSelfIDNotIncluded)
	}

	keygenDone := s.KeygenDone()
	// basic check for each party
	for _, j := range s.PartyIDs {
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

	// do a full validation of secret if keygen is done
	if s.IsSigning() {
		if t := len(s.SignerIDs); t <= s.Threshold || t > s.N() {
			return fmt.Errorf("session.Sign: number of signerIDs is incorrect (should be in [%d+1, %d])", s.Threshold, s.N())
		}
		if !s.SignerIDs.Contains(s.SelfID()) {
			return errors.New("session.Sign: SignerIDs does not contain SelfID")
		}
		if !s.validateSignerSubset() {
			return errors.New("session: signer are not a subset of all parties")
		}
		if !s.PublicKey.Equal(s.computeSignPublicKey()) {
			return errors.New("session: public key computed from signers mismatch")
		}
		// validate secret
		if err := s.Secret.ValidatePublic(s.SigningParties[s.SelfID()]); err != nil {
			return fmt.Errorf("session: secret data: %w", err)
		}
	} else {
		// validate secret
		if err := s.Secret.ValidatePublic(s.Public[s.SelfID()]); err != nil {
			return fmt.Errorf("session: secret data: %w", err)
		}
	}

	// verify the full PublicKey
	if !s.PublicKey.Equal(s.ComputePublicKey()) {
		return errors.New("session: public key mismatch")
	}

	// check SSID again
	ssid, err := s.computeSSID()
	if err != nil {
		return fmt.Errorf("session: failed to generate SSID: %w", err)
	}
	if !bytes.Equal(ssid, s.ssid) {
		return errors.New("session: SSID mismatch")
	}

	return nil
}

// validateSignerSubset makes sure that SignerIDs ⊆ PartyIDs and that SigningParties ⊆ Public
func (s Session) validateSignerSubset() bool {
	for _, partyID := range s.SignerIDs {
		if !s.PartyIDs.Contains(partyID) {
			return false
		}
	}

	for partyID, partyJ := range s.SigningParties {
		otherPartyJ := s.Public[partyID]
		if partyJ.ID != otherPartyJ.ID {
			return false
		}
		if !partyJ.Paillier.Equal(otherPartyJ.Paillier) {
			return false
		}
		if !partyJ.Pedersen.Equal(otherPartyJ.Pedersen) {
			return false
		}
	}
	return true
}

// Hash returns a new hash.Hash function initialized with the full SSID.
// It assumes that the state is in a correct, and can panic if it is not.
// Calling hash.Sum() on the resulting hash function returns the hash of the SSID.
// It compute
// - H(𝔾, q, G_x, t, n, P₁, ..., Pₙ,}
//		if no keygen material is given
// - H(𝔾, q, G_x, t, n, P₁, ..., Pₙ, {(Nⱼ, Sⱼ, Tⱼ)}ⱼ}
//		if keygen has run
// - H(𝔾, q, G_x, t, n, P₁, ..., Pₙ, {(Nⱼ, Sⱼ, Tⱼ)}ⱼ, t', {Pₗ}ₗ, m)
//		if we are signing a message m with t' parties {Pₗ}ₗ,
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
	} // Gₓ

	// write t
	binary.BigEndian.PutUint64(intBuffer, uint64(s.Threshold))

	// write PartyIDs (with n)
	if err = h.WriteAny(s.PartyIDs); err != nil {
		return nil, fmt.Errorf("session.Hash: write PartyIDs: %w", err)
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
	for _, partyID := range s.PartyIDs {
		partyI := s.Public[partyID]

		// Write ECDSA public key
		if err = h.WriteAny(partyI.ECDSA); err != nil {
			return nil, fmt.Errorf("session.Hash: party %s, write ECDSA: %w", partyID, err)
		}

		// write N,S,T
		// we don't write the paillier key since it is assumed to be the same as the N from the Pedersen parameters.
		if err = h.WriteAny(partyI.Pedersen); err != nil {
			return nil, fmt.Errorf("session.Hash: party %s, write Pedersen: %w", partyID, err)
		}
	}

	// return early if we aren't signing
	if !s.IsSigning() {
		return h, nil
	}

	// write SignerIDs
	if err = h.WriteAny(s.SignerIDs); err != nil {
		return nil, fmt.Errorf("session.Hash: write SignerIDs: %w", err)
	}

	// write Message
	if _, err = h.Write(s.Message); err != nil {
		return nil, fmt.Errorf("session.Hash: write Message: %w", err)
	}

	return h, nil
}

// ComputePublicKey returns an ecdsa.PublicKey computed via Lagrange interpolation
// of all public shares.
func (s *Session) ComputePublicKey() *ecdsa.PublicKey {
	sum := curve.NewIdentityPoint()
	tmp := curve.NewIdentityPoint()
	for partyID, partyJ := range s.Public {
		lagrange := s.PartyIDs.Lagrange(partyID)
		tmp.ScalarMult(lagrange, partyJ.ECDSA)
		sum.Add(sum, tmp)
	}
	return sum.ToPublicKey()
}

func (s Session) computeSignPublicKey() *ecdsa.PublicKey {
	sum := curve.NewIdentityPoint()
	for _, partyJ := range s.SigningParties {
		sum.Add(sum, partyJ.ECDSA)
	}
	return sum.ToPublicKey()
}

// Clone performs a deep copy of a all fields. In particular, it copies all public party data
// as well as the secret.
func (s *Session) Clone() *Session {
	public2 := make(map[party.ID]*party.Public, len(s.Public))
	for j, publicJ := range s.Public {
		public2[j] = publicJ.Clone()
	}

	ssid2 := make([]byte, params.HashBytes)
	copy(ssid2, s.ssid)

	s2 := &Session{
		group:     s.group,
		PartyIDs:  s.PartyIDs.Copy(),
		Threshold: s.Threshold,
		Public:    public2,
		Secret:    s.Secret.Clone(),
		PublicKey: &(*s.PublicKey),
		ssid:      ssid2,
	}

	if s.IsSigning() {
		signers2 := make(map[party.ID]*party.Public, len(s.SigningParties))
		for j, publicJ := range s.SigningParties {
			signers2[j] = publicJ.Clone()
		}
		s2.SigningParties = signers2
		s2.SignerIDs = s.SignerIDs.Copy()
		s2.Message = append([]byte{}, s.Message...)
	}
	return s2
}

// SelfID returns the ID of the party we have the secrets for
func (s Session) SelfID() party.ID {
	return s.Secret.ID
}

// IsSigning returns true if we are in a signing session
func (s Session) IsSigning() bool {
	return len(s.Message) != 0 && len(s.SignerIDs) != 0
}

// SelfIndex returns the index of the party in PartyIDs that we have the secrets for, in the list of parties in the protocol.
// If we are in a Sign session we return the index in SignerIDs.
func (s Session) SelfIndex() int {
	if s.IsSigning() {
		return s.SignerIDs.GetIndex(s.SelfID())
	}
	return s.PartyIDs.GetIndex(s.SelfID())
}

// SetSecret sets the Secret field are returns an error if validation fails
func (s *Session) SetSecret(secret *party.Secret) error {
	s.Secret = secret
	return s.Validate()
}

// Sign sets the parameters of the session to sign a message.
func (s *Session) Sign(signerIDs party.IDSlice, message []byte) error {
	if s.IsSigning() {
		return errors.New("session.Sign: Session is already in Sign mode")
	}

	if len(message) == 0 {
		return errors.New("session.Sign: message is nil")
	}

	t := len(signerIDs)
	for _, signerID := range signerIDs {
		if !s.PartyIDs.Contains(signerID) {
			return fmt.Errorf("session.Sign: PartyIDs does not contain party %s", signerID)
		}
	}
	s.SignerIDs = signerIDs.Copy()
	s.SignerIDs.Sort()

	signers := make(map[party.ID]*party.Public, t)
	for _, idJ := range s.SignerIDs {
		signers[idJ] = s.Public[idJ].Clone()
		lagrange := s.SignerIDs.Lagrange(idJ)
		signers[idJ].ECDSA.ScalarMult(lagrange, signers[idJ].ECDSA)
	}
	s.SigningParties = signers

	lagrangeSelf := s.SignerIDs.Lagrange(s.SelfID())
	s.Secret.ECDSA = s.Secret.ECDSA.Multiply(s.Secret.ECDSA, lagrangeSelf)

	s.Message = append([]byte{}, message...)

	if err := s.RecomputeSSID(); err != nil {
		return fmt.Errorf("session.Sign: %w", err)
	}
	return s.Validate()
}
