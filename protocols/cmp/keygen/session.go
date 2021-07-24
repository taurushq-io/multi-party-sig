package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/taurusgroup/cmp-ecdsa/internal/writer"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

// Session represents the SSID after having performed a keygen/refresh operation.
// It represents ssid = (sid, (N₁, s₁, t₁), …, (Nₙ, sₙ, tₙ))
// where sid = (𝔾, t, n, P₁, …, Pₙ).
type Session struct {
	// group for signature
	group elliptic.Curve

	// threshold is the integer t which defines the maximum number of corruptions tolerated for this session.
	threshold int

	// public maps party.ID to party. It contains all public information associated to a party.
	// When keygen has not yet run, all party.Public should contain only the ID
	public map[party.ID]*Public

	// publicKey is the full ECDSA public key
	publicKey *ecdsa.PublicKey

	// rid is a 32 byte random identifier generated for this session
	rid RID
}

// newSession creates a session from given keygen material, and performs full verification.
// If SSID is given, then it checked against the recomputed one.
// No copy of the given data is performed.
func newSession(threshold int, publicInfo map[party.ID]*Public, rid RID) (*Session, error) {
	n := len(publicInfo)
	if n == 0 {
		return nil, errors.New("helper: partyIDs is empty")
	}
	// verify number of parties w.r.t. threshold
	// want 0 ⩽ threshold ⩽ n-1
	if !(0 <= threshold && threshold <= n-1) {
		return nil, fmt.Errorf("helper: threshold %d is invalid", threshold)
	}

	s := &Session{
		group:     secp256k1.S256(), // todo change to allow different groups
		threshold: threshold,
		public:    publicInfo,
		rid:       rid.Copy(),
	}
	s.publicKey = s.computePublicKey()

	if err := s.Validate(); err != nil {
		return nil, err
	}

	return s, nil
}

// Threshold returns the maximum number of corruption tolerated, i.e. Threshold() + 1 is the minimum number
// of parties' shares required to reconstruct the secret/sign a message.
func (s Session) Threshold() int { return s.threshold }

// Public returns the public key material we have stored for the party with the given id.
func (s Session) Public(id party.ID) *Public { return s.public[id] }

// PublicKey returns the group's public ECDSA key.
func (s Session) PublicKey() *ecdsa.PublicKey { return s.publicKey }

func (s Session) Validate() error {
	n := len(s.public)
	if n == 0 {
		return errors.New("session: partyIDs is empty")
	}
	// verify number of parties w.r.t. threshold
	// want 0 ⩽ threshold ⩽ n-1
	if !(0 <= s.threshold && s.threshold <= n-1) {
		return fmt.Errorf("session: threshold %d is invalid", s.threshold)
	}

	for j, publicJ := range s.public {
		// validate public
		if err := publicJ.Validate(); err != nil {
			return fmt.Errorf("session: party %s: %w", j, err)
		}
	}

	return nil
}

func (s Session) ValidateSecret(secret *Secret) error {
	// verify our ID is present
	public, ok := s.public[secret.ID]
	if !ok {
		return errors.New("session: no public data for secret")
	}
	if err := secret.ValidatePublic(public); err != nil {
		return fmt.Errorf("session: secret data: %w", err)
	}
	return nil
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

// WriteTo implements io.WriterTo interface.
func (s Session) WriteTo(w io.Writer) (total int64, err error) {
	var n int64

	// write t
	n, err = writer.WriteWithDomain(w, Threshold(s.threshold))
	total += n
	if err != nil {
		return
	}

	// write rid
	n, err = writer.WriteWithDomain(w, s.rid)
	total += n
	if err != nil {
		return
	}

	for _, j := range s.PartyIDs() {
		// write Xⱼ
		n, err = writer.WriteWithDomain(w, s.public[j].ECDSA)
		total += n
		if err != nil {
			return
		}
		// write Nⱼ, sⱼ, tⱼ
		n, err = writer.WriteWithDomain(w, s.public[j].Pedersen)
		total += n
		if err != nil {
			return
		}
	}

	return
}

// Domain implements writer.WriterToWithDomain.
func (s Session) Domain() string {
	return "CMP Session"
}

func (s Session) PartyIDs() party.IDSlice {
	ids := make([]party.ID, 0, len(s.public))
	for j := range s.public {
		ids = append(ids, j)
	}
	return party.NewIDSlice(ids)
}

var _ json.Marshaler = (*Session)(nil)
var _ json.Unmarshaler = (*Session)(nil)

type jsonSession struct {
	// TODO include Group information
	//Group string `json:"group"`
	Threshold int                  `json:"threshold"`
	PublicKey *curve.Point         `json:"public_key"`
	RID       []byte               `json:"rid"`
	Public    map[party.ID]*Public `json:"public"`
}

func (s Session) MarshalJSON() ([]byte, error) {
	x := jsonSession{
		Threshold: s.threshold,
		PublicKey: curve.FromPublicKey(s.publicKey),
		RID:       s.rid[:],
		Public:    s.public,
	}
	return json.Marshal(x)
}

func (s *Session) UnmarshalJSON(b []byte) error {
	var x jsonSession
	err := json.Unmarshal(b, &x)
	if err != nil {
		return fmt.Errorf("session: unmarshal failed: %w", err)
	}

	s2, err := newSession(x.Threshold, x.Public, RID(x.RID).Copy())
	if err != nil {
		return err
	}

	if !x.PublicKey.Equal(curve.FromPublicKey(s2.publicKey)) {
		return errors.New("session: unmarshal failed: public key mismatch")
	}

	*s = *s2
	return nil
}
