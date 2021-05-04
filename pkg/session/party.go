package session

import (
	"errors"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

type Public struct {
	ID party.ID

	ecdsaShare *curve.Point
	n          *big.Int
	s, t       *big.Int
}

func NewPublic(id party.ID, public *curve.Point, ped *pedersen.Parameters) *Public {
	var n, s, t big.Int
	p := &Public{ID: id}

	if public != nil {
		p.ecdsaShare = curve.NewIdentityPoint().Set(public)
	}
	if ped != nil {
		p.n = n.Set(ped.N)
		p.s = s.Set(ped.S)
		p.t = t.Set(ped.T)
	}
	return p
}

func (p *Public) ShareECDSA() *curve.Point {
	var pk curve.Point
	return pk.Set(p.ecdsaShare)
}

func (p *Public) Paillier() *paillier.PublicKey {
	return paillier.NewPublicKey(p.n)
}

func (p *Public) Pedersen() *pedersen.Parameters {
	var n, s, t big.Int
	n.Set(p.n)
	s.Set(p.s)
	t.Set(p.t)
	return &pedersen.Parameters{
		N: &n,
		S: &s,
		T: &t,
	}
}

func (p *Public) state() State {
	allNil := p.n == nil && p.s == nil && p.t == nil
	noneNil := p.n != nil && p.s != nil && p.t != nil

	if p.ecdsaShare == nil && allNil {
		return StateInit
	}
	if p.ecdsaShare != nil && allNil {
		return StateKeygen
	}
	if p.ecdsaShare != nil && noneNil {
		return StateRefresh
	}

	return StateError
}

func (p *Public) writeToHash(h *hash.Hash) error {
	var err error

	s := p.state()
	if s == StateError {
		return errors.New("invalid parameters")
	}

	if _, err = h.Write([]byte(p.ID)); err != nil {
		return err
	}

	if s >= StateKeygen {
		if _, err = h.Write(p.ecdsaShare.Bytes()); err != nil {
			return err
		}
	}

	if s == StateRefresh {
		if err = h.WriteAny(p.n, p.s, p.t); err != nil {
			return err
		}
	}

	return nil
}

func (p *Public) valid() error {
	s := p.state()
	switch {
	case s == StateError:
		return errors.New("invalid parameters")
	case s >= StateKeygen:
		if p.ecdsaShare.IsIdentity() {
			return errors.New("ecdsa key is 0")
		}
	case s >= StateRefresh:
		ped := &pedersen.Parameters{
			N: p.n,
			S: p.s,
			T: p.n,
		}
		if !ped.IsValid() {
			return errors.New("pedersen invalid")
		}

		if p.n.BitLen() != params.PaillierBits {
			return errors.New("n has invalid size")
		}
	}

	return nil
}
