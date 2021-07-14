package session

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/internal/writer"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

// Sign is a Session which can be used to initiate a signing protocol.
// It contains all the information included in a Refresh session, except that the
// public shares are normalized by their Lagrange coefficients, making it an additive sharing.
// It is initialized with the set set of parties P'₁,… , P'ₛ who are chosen to sign the message,
// along with the message m itself.
type Sign struct {
	*Refresh

	signerIDs party.IDSlice
	secret    *party.Secret
	public    map[party.ID]*party.Public

	ssid []byte

	message []byte
}

// NewSignSession creates a session.Sign given a base session which contains existing key material.
// The set of 's' signers P'₁,…, P'ₛ must be a subset of the original party IDs and must include this party's ID.
// The message must not be nil.
func NewSignSession(base *Refresh, signerIDs []party.ID, message []byte) (*Sign, error) {
	if err := base.Validate(); err != nil {
		return nil, err
	}
	secret := base.Secret().Clone()

	correctPartyIDs := make(party.IDSlice, 0, len(signerIDs))
	public := make(map[party.ID]*party.Public, len(signerIDs))
	for _, id := range signerIDs {
		if !base.PartyIDs().Contains(id) {
			return nil, fmt.Errorf("session: base does not contain party: %v", id)
		}
		public[id] = base.Public(id).Clone()

		correctPartyIDs = append(correctPartyIDs, id)
	}
	correctPartyIDs.Sort()

	// normalize public shares
	for idJ, publicJ := range public {
		lagrange := correctPartyIDs.Lagrange(idJ)
		publicJ.ECDSA.ScalarMult(lagrange, publicJ.ECDSA)

		// update out share as well
		if idJ == base.SelfID() {
			secret.ECDSA.Multiply(lagrange, secret.ECDSA)
		}
	}

	s := &Sign{
		Refresh:   base,
		signerIDs: correctPartyIDs,
		secret:    secret,
		public:    public,
		message:   message,
	}
	s.ssid = computeSSID(s)
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// PartyIDs is a subset of the 's' original PartyIDs P'₁,…, P'  which are signing a message
func (s Sign) PartyIDs() party.IDSlice {
	return s.signerIDs
}

// N returns the number of parties 's' performing the signing
func (s Sign) N() int {
	return len(s.signerIDs)
}

// Public returns the public data associated to the requested party,
// with the ECDSA key normalized to the signing set
func (s Sign) Public(id party.ID) *party.Public {
	return s.public[id]
}

// SSID returns Hash(sid, {(Nⱼ, Sⱼ, Tⱼ)}ⱼ, s, P'₁,…, P'ₛ, m)
func (s Sign) SSID() []byte {
	return s.ssid
}

// Secret returns this party's secret data, where the ECDSA secret key share has been normalized so that it is an
// additive share of the full ECDSA secret key.
func (s Sign) Secret() *party.Secret {
	return s.secret
}

// Hash returns a new hash.Hash function initialized with the full SSID.
// It assumes that the state is in a correct, and can panic if it is not.
// Calling hash.Sum() on the resulting hash function returns the hash of the SSID.
// The hash.Hash function is initialized with the following:
//   Hash(𝔾, q, G_x, t, n, P₁, …, Pₙ, {(Nⱼ, Sⱼ, Tⱼ)}ⱼ, s, P'₁,… , P'ₛ, m)
//   = Hash(sid, {(Nⱼ, Sⱼ, Tⱼ)}ⱼ, s, P'₁,… , P'ₛ, m)
// In particular, it simply appends the data about the set of signers and the message being signed, to the
// hash function initialized by a Refresh session.
func (s Sign) Hash() *hash.Hash {
	h := s.Keygen.Hash()

	// write SignerIDs
	_, _ = h.WriteAny(s.signerIDs)

	// write Message
	_, _ = h.WriteAny(&writer.BytesWithDomain{
		TheDomain: "Message",
		Bytes:     s.message,
	})

	return h
}

func (s Sign) Clone() Session {
	public2 := make(map[party.ID]*party.Public, len(s.public))
	for j, publicJ := range s.public {
		public2[j] = publicJ.Clone()
	}

	s2 := &Sign{
		Refresh:   s.Refresh.Clone().(*Refresh),
		signerIDs: s.signerIDs.Copy(),
		secret:    s.secret.Clone(),
		public:    public2,
		ssid:      computeSSID(s),
		message:   append([]byte{}, s.message...),
	}

	return s2
}

// Validate performs necessary validation to ensure that the provided key material will allow
// a signature to be generated for the given message and the chosen set of singing parties.
func (s Sign) Validate() error {
	if len(s.message) == 0 {
		return errors.New("session: message cannot be nil")
	}
	for _, partyID := range s.signerIDs {
		if !s.Refresh.PartyIDs().Contains(partyID) {
			return fmt.Errorf("session.Sign: Base Session does not contain ID %v", partyID)
		}
	}
	for partyID, partyJ := range s.public {
		otherPartyJ := s.Refresh.Public(partyID)
		if partyJ.ID != otherPartyJ.ID {
			return fmt.Errorf("session.Sign: public data of party with ID %v does not match", partyID)
		}
		if !partyJ.Paillier.Equal(otherPartyJ.Paillier) {
			return fmt.Errorf("session.Sign: Paillier public key of party with ID %v does not match", partyID)
		}
		if !partyJ.Pedersen.Equal(otherPartyJ.Pedersen) {
			return fmt.Errorf("session: Pedersen parameters of party with ID %v does not match", partyID)
		}
	}
	return validate(s)
}

func (s Sign) computePublicKey() *ecdsa.PublicKey {
	sum := curve.NewIdentityPoint()
	for _, partyJ := range s.public {
		sum.Add(sum, partyJ.ECDSA)
	}
	return sum.ToPublicKey()
}

// Message returns the message which will be signed with this session.
func (s Sign) Message() []byte {
	return s.message
}
