package session

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

// Session holds all data necessary to initiate a protocol.
type Session interface {
	// Curve returns the elliptic curve used in the session
	Curve() elliptic.Curve
	// Threshold the integer t which defines the maximum number of corruptions tolerated for this session.
	Threshold() int

	// PartyIDs is the list of parties participating in this session
	PartyIDs() party.IDSlice

	// N is the number of parties participating in this session
	N() int

	// Public returns the associated public data to the party with id.
	// If this party does not exist, returns nil
	Public(id party.ID) *party.Public

	// SSID is the hash of the SSID used to
	SSID() []byte

	// Secret returns the secret key material ECDSA, Paillier and RID
	Secret() *party.Secret

	// SelfID returns the ID of the host party
	SelfID() party.ID

	// SelfIndex returns the index i such that PartyIDs()[i] == SelfID()
	SelfIndex() int

	// PublicKey is the ECDSA public key for the set of parties
	PublicKey() *ecdsa.PublicKey

	// Hash returns a new hash.Hash function initialized with the SSID information
	Hash() *hash.Hash

	// Clone returns a deep copy of the session
	Clone() Session

	// Validate performs a thorough validation of all data contained in the session.
	// Returns an error if an inconsistency is found
	Validate() error

	computePublicKey() *ecdsa.PublicKey
}

func computeSSID(s Session) []byte {
	ssid, _ := s.Hash().ReadBytes(nil)
	return ssid
}

func validate(s Session) error {
	if len(s.PartyIDs()) == 0 {
		return errors.New("session: PartyIDs is empty")
	}
	if !s.PartyIDs().Sorted() {
		return errors.New("session: PartyIDs are not sorted")
	}
	if !s.PartyIDs().Contains(s.SelfID()) {
		return fmt.Errorf("session: PartyIDs does not contain SelfID %v", s.SelfID())
	}
	for i := range s.PartyIDs() {
		if i == 0 {
			continue
		}
		if s.PartyIDs()[i-1] == s.PartyIDs()[i] {
			return fmt.Errorf("session: PartyIDs contains duplicate: %v", s.PartyIDs()[i])
		}
	}

	secret := s.Secret()
	if secret == nil {
		return errors.New("session: Secret is not yet set")
	}
	// verify our ID is present
	if secret.ID != s.SelfID() {
		return errors.New("session: selfID mismatch")
	}

	if len(s.SSID()) != params.SizeSSID {
		return errors.New("session: SSID has wrong length")
	}

	// verify SSID content
	if !bytes.Equal(s.SSID(), computeSSID(s)) {
		return errors.New("session: SSID mismatch")
	}

	// verify the full publicKey
	if pk := s.computePublicKey(); pk != nil && !s.PublicKey().Equal(pk) {
		return errors.New("session: public key mismatch")
	}

	// verify number of parties w.r.t. threshold
	if t := len(s.PartyIDs()); t <= s.Threshold() || t > s.N() {
		return fmt.Errorf("session: number of parties is incorrect (should be in [%d+1, %d])", s.Threshold(), s.N())
	}

	// validate secret
	if err := secret.ValidatePublic(s.Public(s.SelfID())); err != nil {
		return fmt.Errorf("session: secret data: %w", err)
	}

	hasECDSA := secret.ECDSA != nil
	hasPaillier := secret.Paillier != nil

	// basic check for each party
	for _, j := range s.PartyIDs() {
		publicJ := s.Public(j)
		if publicJ == nil {
			return fmt.Errorf("session: party %s not included in Public", j)
		}

		// check ID
		if publicJ.ID != j {
			return fmt.Errorf("session: party %s: ID mismatch", j)
		}

		// check ECDSA
		if hasECDSA && publicJ.ECDSA == nil {
			return fmt.Errorf("session: party %s: has no ECDSA public key", j)
		}

		// check Paillier/Pedersen
		if hasPaillier && (publicJ.Paillier == nil || publicJ.Pedersen == nil) {
			return fmt.Errorf("session: party %s: has no Paillier/Pedersen data", j)
		}

		// validate public
		if err := publicJ.Validate(); err != nil {
			return fmt.Errorf("session: party %s: %w", j, err)
		}

	}
	return nil
}
