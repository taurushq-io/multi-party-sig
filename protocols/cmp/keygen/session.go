package keygen

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/taurusgroup/cmp-ecdsa/internal/writer"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

// sid represents the SID of the paper consisting of (𝔾, t, n, P₁, …, Pₙ)
type sid struct {
	// group for signature
	group elliptic.Curve

	// partyIDs is the full list of party's IDs
	partyIDs party.IDSlice

	// threshold is the integer t which defines the maximum number of corruptions tolerated for this session.
	threshold int

	sid []byte
}

// Session represents the SSID after having performed a keygen/refresh operation.
type Session struct {
	*sid

	// public maps party.ID to party. It contains all public information associated to a party.
	// When keygen has not yet run, all party.Public should contain only the ID
	public map[party.ID]*Public

	// publicKey is the full ECDSA public key
	publicKey *ecdsa.PublicKey

	// rid is a 32 byte random identifier generated for this session
	rid RID

	// ssid is a cached hash of SSID
	// It corresponds to Hash(G, n, t, P₁, …, Pₙ, aux_info)
	ssid []byte
}

func newSID(partyIDs []party.ID, threshold int) (*sid, error) {
	ids := party.NewIDSlice(partyIDs)

	s := &sid{
		group:     secp256k1.S256(), // todo change to allow different groups
		partyIDs:  ids,
		threshold: threshold,
	}

	// get SSID hash
	s.sid = s.Hash().ReadBytes(nil)

	if err := s.validate(); err != nil {
		return nil, err
	}

	return s, nil
}

// newSession creates a session from given keygen material, and performs full verification.
// If SSID is given, then it checked against the recomputed one.
// No copy of the given data is performed
func newSession(sid *sid, publicInfo map[party.ID]*Public, rid RID) (*Session, error) {
	s := &Session{
		sid:    sid,
		public: publicInfo,
		rid:    rid.Copy(),
	}
	s.publicKey = s.computePublicKey()
	s.ssid = s.Hash().ReadBytes(nil)

	if err := s.Validate(); err != nil {
		return nil, err
	}

	return s, nil
}

// PartyIDs returns the a sorted slice of all the parties in this session
func (s sid) PartyIDs() party.IDSlice { return s.partyIDs }

// N is the total number of parties in this session.
func (s sid) N() int { return len(s.partyIDs) }

// Threshold returns the maximum number of corruption tolerated, i.e. Threshold() + 1 is the minimum number
// of parties' shares required to reconstruct the secret/sign a message.
func (s sid) Threshold() int { return s.threshold }

// Curve returns the curve over which this session is defined.
func (s sid) Curve() elliptic.Curve { return s.group }

// SSID returns the hash of the SID
func (s sid) SSID() []byte { return s.sid }

// SSID returns the hash of the SSID
func (s Session) SSID() []byte { return s.ssid }

// Public returns the public key material we have stored for the party with the given id.
func (s Session) Public(id party.ID) *Public { return s.public[id] }

// PublicKey returns the group's public ECDSA key
func (s Session) PublicKey() *ecdsa.PublicKey { return s.publicKey }

// Hash returns a new hash.Hash function initialized with the full SID.
// It assumes that the state is in a correct, and can panic if it is not.
// Calling hash.Sum() on the resulting hash function returns the hash of the SSID.
// It computes
// - Hash(𝔾, q, G_x, t, n, P₁, …, Pₙ,}
func (s sid) Hash() *hash.Hash {
	intBuffer := make([]byte, 8)

	h := hash.New()

	// Write group information
	// 𝔾
	_, _ = h.WriteAny(&writer.BytesWithDomain{
		TheDomain: "Group Name",
		Bytes:     []byte(s.group.Params().Name),
	})
	// q
	_, _ = h.WriteAny(&writer.BytesWithDomain{
		TheDomain: "Group Order",
		Bytes:     s.group.Params().N.Bytes(),
	})
	// Gₓ
	_, _ = h.WriteAny(&writer.BytesWithDomain{
		TheDomain: "Generator X Coordinate",
		Bytes:     s.group.Params().Gx.Bytes(),
	})

	// write t
	binary.BigEndian.PutUint64(intBuffer, uint64(s.threshold))

	// write PartyIDs (with n)
	_, _ = h.WriteAny(s.partyIDs)

	return h
}

// Hash returns a new hash.Hash function initialized with the full SSID.
// It assumes that the state is in a correct, and can panic if it is not.
// Calling hash.Sum() on the resulting hash function returns the hash of the SSID.
// It computes
// - Hash(𝔾, q, G_x, t, n, P₁, …, Pₙ, {(Nⱼ, Sⱼ, Tⱼ)}ⱼ}
//   = Hash(sid, rid, {(Nⱼ, Sⱼ, Tⱼ)}ⱼ}
func (s Session) Hash() *hash.Hash {
	h := s.sid.Hash()

	// RID (since secret is already set)
	_, _ = h.WriteAny(s.rid)

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

func (s sid) validate() error {
	n := len(s.partyIDs)
	if n == 0 {
		return errors.New("session: partyIDs is empty")
	}
	// verify number of parties w.r.t. threshold
	// want 0 ⩽ threshold ⩽ n-1
	if s.threshold < 0 || n <= s.threshold {
		return fmt.Errorf("session: threshold %d is invalid", s.threshold)
	}

	if len(s.partyIDs) == 0 {
		return errors.New("session: PartyIDs is empty")
	}
	if !s.partyIDs.Sorted() {
		return errors.New("session: PartyIDs are not sorted")
	}
	//if !s.partyIDs.Contains(s.selfID) {
	//	return fmt.Errorf("session: PartyIDs does not contain SelfID %v", s.selfID)
	//}
	if s.partyIDs.ContainsDuplicates() {
		return errors.New("session: PartyIDs contains duplicate")
	}

	return nil
}

func (s Session) Validate() error {
	if err := s.sid.validate(); err != nil {
		return err
	}

	for _, j := range s.partyIDs {
		publicJ, ok := s.public[j]
		if !ok {
			return fmt.Errorf("session: party %s not included in Public", j)
		}
		if publicJ == nil {
			return fmt.Errorf("session: party %s not included in Public", j)
		}

		// check ID
		if publicJ.ID != j {
			return fmt.Errorf("session: party %s: ID mismatch", j)
		}

		// check ECDSA
		if publicJ.ECDSA == nil {
			return fmt.Errorf("session: party %s: has no ECDSA public key", j)
		}

		// check Paillier
		if publicJ.Paillier == nil {
			return fmt.Errorf("session: party %s: has no Paillier data", j)
		}

		// check Pedersen
		if publicJ.Pedersen == nil {
			return fmt.Errorf("session: party %s: has no Pedersen data", j)
		}

		// validate public
		if err := publicJ.Validate(); err != nil {
			return fmt.Errorf("session: party %s: %w", j, err)
		}
	}

	// verify SSID content
	if ssid := s.Hash().ReadBytes(nil); !bytes.Equal(s.ssid, ssid) {
		return errors.New("session: SSID mismatch")
	}

	// verify the full publicKey
	if pk := s.computePublicKey(); !s.publicKey.Equal(pk) {
		return errors.New("session: public key mismatch")
	}

	return nil
}

func (s Session) ValidateSecret(secret *Secret) error {
	// verify our ID is present
	if !s.partyIDs.Contains(secret.ID) {
		return errors.New("session: selfID mismatch")
	}
	//if secret.ID != s.selfID {
	//	return errors.New("session: selfID mismatch")
	//}
	// validate secret
	if err := secret.ValidatePublic(s.public[secret.ID]); err != nil {
		return fmt.Errorf("session: secret data: %w", err)
	}
	return nil
}

// Clone performs a deep copy of a all fields.
func (s sid) Clone() *sid {
	sid2 := make([]byte, params.SizeSSID)
	copy(sid2, s.sid)

	return &sid{
		group:     s.group,
		partyIDs:  s.partyIDs.Copy(),
		threshold: s.threshold,
		sid:       sid2,
	}
}

// Clone performs a deep copy of a all fields.
func (s Session) Clone() *Session {
	public2 := make(map[party.ID]*Public, len(s.public))
	for j, publicJ := range s.public {
		public2[j] = publicJ.Clone()
	}

	ssid2 := make([]byte, params.SizeSSID)
	copy(ssid2, s.ssid)

	s2 := &Session{
		sid:       s.sid.Clone(),
		public:    public2,
		publicKey: &(*s.publicKey),
		rid:       s.rid.Copy(),
		ssid:      ssid2,
	}
	return s2
}

// computePublicKey returns an ecdsa.PublicKey computed via Lagrange interpolation
// of all public shares.
func (s Session) computePublicKey() *ecdsa.PublicKey {
	sum := curve.NewIdentityPoint()
	tmp := curve.NewIdentityPoint()
	for partyID, partyJ := range s.public {
		lagrange := s.PartyIDs().Lagrange(partyID)
		tmp.ScalarMult(lagrange, partyJ.ECDSA)
		sum.Add(sum, tmp)
	}
	return sum.ToPublicKey()
}

var _ json.Marshaler = (*Session)(nil)
var _ json.Unmarshaler = (*Session)(nil)

type jsonSession struct {
	// TODO include Group information
	//Group string `json:"group"`
	Threshold int          `json:"threshold"`
	PublicKey *curve.Point `json:"public_key"`
	RID       []byte       `json:"rid"`
	SSID      []byte       `json:"ssid"`
	Public    []*Public    `json:"public"`
}

func (s Session) MarshalJSON() ([]byte, error) {
	public := make([]*Public, 0, len(s.public))
	for _, j := range s.partyIDs {
		public = append(public, s.public[j])
	}
	x := jsonSession{
		Threshold: s.threshold,
		PublicKey: curve.FromPublicKey(s.publicKey),
		RID:       s.rid[:],
		SSID:      s.ssid,
		Public:    public,
	}
	return json.Marshal(x)
}

func (s *Session) UnmarshalJSON(b []byte) error {
	var x jsonSession
	err := json.Unmarshal(b, &x)
	if err != nil {
		return fmt.Errorf("session: unmarshal failed: %w", err)
	}

	n := len(x.Public)
	public := make(map[party.ID]*Public, n)
	partyIDs := make(party.IDSlice, 0, n)
	for _, partyJ := range x.Public {
		partyIDs = append(partyIDs, partyJ.ID)
		public[partyJ.ID] = partyJ
	}

	sid, err := newSID(partyIDs, x.Threshold)
	if err != nil {
		return fmt.Errorf("session: unmarshal failed: %w", err)
	}

	var rid RID
	rid.FromBytes(x.RID)

	s2, err := newSession(sid, public, rid)
	if err != nil {
		return err
	}

	if !bytes.Equal(x.SSID, s2.ssid) {
		return errors.New("session: unmarshal failed: SSID mismatch")
	}
	if !x.PublicKey.Equal(curve.FromPublicKey(s2.publicKey)) {
		return errors.New("session: unmarshal failed: public key mismatch")
	}

	*s = *s2
	return nil
}

// RID is the unique identifier generated during the keygen
type RID [params.SecBytes]byte

// WriteTo makes ID implement the io.WriterTo interface.
//
// This writes out the content of this ID, in a domain separated way.
func (rid RID) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(rid[:])
	return int64(n), err
}

// Domain implements WriterToWithDomain, and separates this type within hash.Hash.
func (rid RID) Domain() string {
	return "RID"
}

func (rid *RID) FromBytes(b []byte) {
	copy(rid[:], b)
}

func (rid RID) Copy() RID {
	var other RID
	copy(other[:], rid[:])
	return other
}

func (rid RID) Equals(other RID) bool {
	return bytes.Equal(rid[:], other[:])
}
