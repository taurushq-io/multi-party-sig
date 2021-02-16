package zk

import (
	"crypto/rand"
	"github.com/taurusgroup/cmp-ecdsa/arith"
	"math/big"
)

type Pedersen struct {
	N, S, T *big.Int
}

func NewPedersen(NHat, phi *big.Int) *Pedersen {
	r := arith.RandomUnit(NHat)
	lambda, _ := rand.Int(rand.Reader, phi)
	t := new(big.Int).Exp(r, big.NewInt(2), NHat)
	s := new(big.Int).Exp(t, lambda, NHat)

	p := &Pedersen{
		N: NHat,
		S: s,
		T: t,
	}
	return p
}

func (p *Pedersen) SPowXTPowY(x, y *big.Int) *big.Int {
	res := new(big.Int)
	tmp := new(big.Int)
	res.Exp(p.S, x, p.N)
	tmp.Exp(p.T, y, p.N)
	res.Mul(res, tmp)
	res.Mod(res, p.N)
	return res
}
func (p *Pedersen) NHat() *big.Int {
	return p.N
}
