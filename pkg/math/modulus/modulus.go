package modulus

import (
	"github.com/cronokirby/safenum"
)

type Modulus struct {
	// n = p⋅q
	n, p, q *safenum.Modulus
	// pInvQ = pNat⁻¹ (mod q)
	pNat, pInvQ *safenum.Nat
}

func FromN(n *safenum.Modulus) *Modulus {
	return &Modulus{
		n: n,
	}
}

func primePower(p *safenum.Nat, power int) *safenum.Nat {
	pPower := new(safenum.Nat).SetNat(p)
	for i := 0; i < power-1; i++ {
		pPower.Mul(pPower, p, -1)
	}
	return pPower
}

func FromFactors(p, q *safenum.Nat, pPower, qPower int) *Modulus {
	pNat := primePower(p, pPower)
	qNat := primePower(q, qPower)
	nNat := new(safenum.Nat).Mul(pNat, qNat, -1)
	nMod := safenum.ModulusFromNat(nNat)
	pMod := safenum.ModulusFromNat(pNat)
	qMod := safenum.ModulusFromNat(qNat)
	pInvQ := new(safenum.Nat).ModInverse(pNat, qMod)
	return &Modulus{
		n:     nMod,
		p:     pMod,
		q:     qMod,
		pNat:  pNat,
		pInvQ: pInvQ,
	}
}

func (m *Modulus) Modulus() *safenum.Modulus {
	return m.n
}

// ExpI is equivalent to ExpI(x, e, m) and returns xᵉ (mod m).
func (m *Modulus) ExpI(x *safenum.Nat, e *safenum.Int) *safenum.Nat {
	if m.hasFactorization() {
		y := m.Exp(x, e.Abs())
		inverted := new(safenum.Nat).ModInverse(y, m.n)
		y.CondAssign(e.IsNegative(), inverted)
		return y
	}
	return new(safenum.Nat).ExpI(x, e, m.n)
}

// Exp is equivalent to z.Exp(x, e, m)
func (m *Modulus) Exp(x, e *safenum.Nat) *safenum.Nat {
	if m.hasFactorization() {
		var xp, xq safenum.Nat
		xp.Exp(x, e, m.p)
		xq.Exp(x, e, m.q)
		r := xq.ModSub(&xq, &xp, m.n)
		r.ModMul(r, m.pInvQ, m.n)
		r.ModMul(r, m.pNat, m.n)
		r.ModAdd(r, &xp, m.n)
		return r
	}
	return new(safenum.Nat).Exp(x, e, m.n)
}

func (m Modulus) hasFactorization() bool {
	return m.p != nil && m.q != nil && m.pNat != nil && m.pInvQ != nil
}
