package session

import (
	"errors"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

type Secret struct {
	ID party.ID

	ecdsaShare           *curve.Scalar
	paillierP, paillierQ *big.Int
}

func (s *Secret) ShareECDSA() *curve.Scalar {
	var sk curve.Scalar
	return sk.Set(s.ecdsaShare)
}

func (s *Secret) Paillier() *paillier.SecretKey {
	var n, phi, tmp big.Int

	n.Mul(s.paillierP, s.paillierQ)

	one := big.NewInt(1)
	phi.Sub(s.paillierP, one)
	tmp.Sub(s.paillierQ, one)
	phi.Mul(&phi, &tmp)

	pk := paillier.NewPublicKey(&n)
	return paillier.NewSecretKey(&phi, pk)
}

func (s *Secret) validForParty(p *Public) error {
	if s.ID != p.ID {
		return errors.New("party ID mismatch")
	}
	st := s.state()

	if st != p.state() {
		return errors.New("state mismatch")
	}

	if st >= StateKeygen {
		if s.ecdsaShare.IsZero() {
			return errors.New("ecdsa share is 0")
		}

		pk := curve.NewIdentityPoint().ScalarBaseMult(s.ecdsaShare)
		if !pk.Equal(p.ecdsaShare) {
			return errors.New("ecdsa key mismatch")
		}
	}

	if st >= StateRefresh {
		n := new(big.Int).Mul(s.paillierP, s.paillierQ)
		if n.Cmp(p.n) != 0 {
			return errors.New("paillier mismatch")
		}

		if s.paillierQ.BitLen() != params.BlumPrimeBits {
			return errors.New("prime q has wrong length")
		}

		if s.paillierP.BitLen() != params.BlumPrimeBits {
			return errors.New("prime p has wrong length")
		}
	}

	return nil
}

func (s *Secret) state() State {
	if s.ecdsaShare == nil && s.paillierP == nil && s.paillierQ == nil {
		return StateInit
	}
	if s.ecdsaShare != nil && s.paillierP == nil && s.paillierQ == nil {
		return StateKeygen
	}
	if s.ecdsaShare != nil && s.paillierP != nil && s.paillierQ != nil {
		return StateRefresh
	}

	return StateError
}
