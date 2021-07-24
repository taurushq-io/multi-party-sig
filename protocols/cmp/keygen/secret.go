package keygen

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

type Secret struct {
	ID party.ID `json:"id"`

	// ECDSA is a party's share xᵢ of the secret ECDSA x
	ECDSA *curve.Scalar `json:"ecdsa"`

	// Paillier is a party's Paillier private key
	Paillier *paillier.SecretKey `json:"paillier"`
}

// ValidatePublic checks whether Secret is compatible with the given Public data.
func (s *Secret) ValidatePublic(p *Public) error {
	if p == nil || p.Pedersen == nil || p.Paillier == nil || p.ECDSA == nil {
		return errors.New("secret: p is nil")
	}

	// check for empty fields
	if s.ID == "" || s.ECDSA == nil || s.Paillier == nil {
		return errors.New("secret: one or more fields are empty")
	}

	// is our ECDSA key 0
	if s.ECDSA.IsZero() {
		return errors.New("secret: ECDSA share is 0")
	}

	// check Paillier
	if err := s.Paillier.Validate(); err != nil {
		return fmt.Errorf("secret: %w", err)
	}

	// is the public ECDSA key equal
	pk := curve.NewIdentityPoint().ScalarBaseMult(s.ECDSA)
	if !pk.Equal(p.ECDSA) {
		return errors.New("secret: ECDSA key mismatch")
	}

	// is our public key for paillier the same?
	if !s.Paillier.PublicKey.Equal(p.Paillier) {
		return errors.New("secret: Paillier key mismatch")
	}

	return nil
}

func (s *Secret) Clone() *Secret {
	return &Secret{
		ID:       s.ID,
		ECDSA:    curve.NewScalar().Set(s.ECDSA),
		Paillier: s.Paillier.Clone(),
	}
}
