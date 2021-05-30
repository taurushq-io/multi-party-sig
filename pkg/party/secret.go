package party

import (
	"errors"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
)

type Secret struct {
	ID ID

	// ECDSA is a party's share xᵢ of the secret ECDSA x
	ECDSA *curve.Scalar

	// Paillier is a party's
	Paillier *paillier.SecretKey
}

func NewSecret(id ID, ecdsaShare *curve.Scalar, p, q *big.Int) *Secret {
	var n, phi, tmp big.Int

	n.Mul(p, q)

	one := big.NewInt(1)
	phi.Sub(p, one)
	tmp.Sub(q, one)
	phi.Mul(&phi, &tmp)

	pk := paillier.NewPublicKey(&n)

	return &Secret{
		ID:       id,
		ECDSA:    curve.NewScalar().Set(ecdsaShare),
		Paillier: paillier.NewSecretKey(&phi, pk),
	}
}

// IsValid checks whether Secret is compatible with the given Public data
func (s *Secret) IsValid(p *Public) error {
	if p == nil {
		return errors.New("public cannot be nil")
	}

	if s.ID != p.ID {
		return errors.New("party ID mismatch")
	}

	if s.ECDSA == nil && s.Paillier != nil {
		return errors.New("ecdsa cannot be nil when Paillier is set")
	}

	if s.ECDSA != nil {
		if p.ECDSA == nil {
			return errors.New("public must contain ECDSA key")
		}

		if s.ECDSA.IsZero() {
			return errors.New("ecdsa share is 0")
		}

		pk := curve.NewIdentityPoint().ScalarBaseMult(s.ECDSA)
		if !pk.Equal(p.ECDSA) {
			return errors.New("ecdsa key mismatch")
		}
	}

	if s.Paillier != nil {
		if p.Pedersen == nil {
			return errors.New("public must contain Paillier key")
		}

		if !s.Paillier.PublicKey().Equal(p.Paillier) {
			return errors.New("paillier mismatch")
		}
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
