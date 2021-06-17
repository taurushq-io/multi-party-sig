package session

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

type SignSession struct {
	*KeygenSession

	signerIDs party.IDSlice
	secret    *party.Secret
	public    map[party.ID]*party.Public

	ssid []byte

	message []byte
}

func NewSignSession(base Session, signerIDs []party.ID, message []byte) (*SignSession, error) {
	if _, ok := base.(*KeygenSession); !ok {
		return nil, errors.New("session: base must of type Session")
	}
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

	s := &SignSession{
		KeygenSession: base.(*KeygenSession),
		signerIDs:     correctPartyIDs,
		secret:        secret,
		public:        public,
		message:       message,
	}
	s.ssid = computeSSID(s)
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// PartyIDs is a subset of of the original PartyIDs which are signing a message
func (s SignSession) PartyIDs() party.IDSlice {
	return s.signerIDs
}

// N returns the number of parties performing the signing
func (s SignSession) N() int {
	return len(s.signerIDs)
}

// Public returns the public data associated to the requested party,
// with the ECDSA key normalized to the signing set
func (s SignSession) Public(id party.ID) *party.Public {
	return s.public[id]
}

func (s SignSession) SSID() []byte {
	return s.ssid
}

func (s SignSession) Secret() *party.Secret {
	return s.secret
}

// Hash returns a new hash.Hash function initialized with the full SSID.
// It assumes that the state is in a correct, and can panic if it is not.
// Calling hash.Sum() on the resulting hash function returns the hash of the SSID.
// It computes
// - Hash(𝔾, q, G_x, t, n, P₁, ..., Pₙ, {(Nⱼ, Sⱼ, Tⱼ)}ⱼ, t', {Pₗ}ₗ, m)
//		if we are signing a message m with t' parties {Pₗ}ₗ,
func (s SignSession) Hash() *hash.Hash {
	h := s.BaseSession.Hash()

	// write SignerIDs
	_, _ = h.WriteAny(s.signerIDs)

	// write Message
	_, _ = h.Write(s.message)

	return h
}

func (s SignSession) Clone() Session {
	public2 := make(map[party.ID]*party.Public, len(s.public))
	for j, publicJ := range s.public {
		public2[j] = publicJ.Clone()
	}

	s2 := &SignSession{
		KeygenSession: s.KeygenSession.Clone().(*KeygenSession),
		signerIDs:     s.signerIDs.Copy(),
		secret:        s.secret.Clone(),
		public:        public2,
		ssid:          computeSSID(s),
		message:       append([]byte{}, s.message...),
	}

	return s2
}

func (s SignSession) Validate() error {
	if len(s.message) == 0 {
		return errors.New("session: message cannot be nil")
	}
	for _, partyID := range s.signerIDs {
		if !s.KeygenSession.PartyIDs().Contains(partyID) {
			return fmt.Errorf("session.Sign: Base Session does not contain ID %v", partyID)
		}
	}
	for partyID, partyJ := range s.public {
		otherPartyJ := s.KeygenSession.Public(partyID)
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

func (s SignSession) computePublicKey() *ecdsa.PublicKey {
	sum := curve.NewIdentityPoint()
	for _, partyJ := range s.public {
		sum.Add(sum, partyJ.ECDSA)
	}
	return sum.ToPublicKey()
}

func (s SignSession) Message() []byte {
	return s.message
}
