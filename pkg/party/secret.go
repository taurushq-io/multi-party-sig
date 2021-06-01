package party

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

type Secret struct {
	ID ID `json:"id"`

	// ECDSA is a party's share xᵢ of the secret ECDSA x
	ECDSA *curve.Scalar `json:"ecdsa"`

	// Paillier is a party's
	Paillier *paillier.SecretKey `json:"paillier"`

	// RID is the random ID generated during the keygen
	RID []byte `json:"rid"`
}

// Validate checks whether the Secret adheres to the protocol.
func (s *Secret) Validate() error {
	if s.ID == "" {
		return errors.New("party.Secret: ID cannot be empty")
	}

	// no other key material is set, we return early
	if s.preKeygen() {
		return nil
	}

	// nil and length checks
	if s.ECDSA == nil {
		return errors.New("party.Secret: ECDSA private share cannot be nil")
	}
	if s.Paillier == nil {
		return errors.New("party.Secret: Paillier private key cannot be nil")
	}
	if len(s.RID) != params.SecBytes {
		return errors.New("party.Secret: RID has wrong length")
	}

	// is our ECDSA key 0
	if s.ECDSA.IsZero() {
		return errors.New("party.Secret: ECDSA share is 0")
	}

	// check Paillier
	if err := s.Paillier.Validate(); err != nil {
		return fmt.Errorf("party.Secret: %w", err)
	}

	return nil
}

func (s Secret) preKeygen() bool {
	return s.ECDSA == nil && s.Paillier == nil && len(s.RID) == 0
}

// KeygenDone returns true if all fields resulting from a keygen are non nil
func (s Secret) KeygenDone() bool {
	return s.ECDSA != nil && s.Paillier != nil && len(s.RID) != 0
}

// ValidatePublic checks whether Secret is compatible with the given Public data
func (s *Secret) ValidatePublic(p *Public) error {
	if p == nil {
		return errors.New("party.Secret: Public cannot be nil")
	}

	// validate Secret standalone
	// this ensures that either all of ECDSA, Paillier RID are set, or none are
	if err := s.Validate(); err != nil {
		return err
	}

	if s.ID != p.ID {
		return errors.New("party.Secret: ID mismatch")
	}

	// if both are in a pre-keygen state then we don' check the rest
	if s.preKeygen() && p.preKeygen() {
		return nil
	}

	// check that both structs have all fields set
	// this ensures fields are not nil
	if !(s.KeygenDone() && p.KeygenDone()) {
		return errors.New("party.Secret: Public and Secret do not have the all fields set the same")
	}

	// is the public ECDSA key equal
	pk := curve.NewIdentityPoint().ScalarBaseMult(s.ECDSA)
	if !pk.Equal(p.ECDSA) {
		return errors.New("party.Secret: ECDSA key mismatch")
	}

	// is our public key for paillier the same?
	if !s.Paillier.PublicKey().Equal(p.Paillier) {
		return errors.New("party.Secret: Paillier key mismatch")
	}

	return nil
}

func (s *Secret) Clone() *Secret {
	return &Secret{
		ID:       s.ID,
		ECDSA:    curve.NewScalar().Set(s.ECDSA),
		Paillier: s.Paillier.Clone(),
		RID:      append([]byte{}, s.RID...),
	}
}
