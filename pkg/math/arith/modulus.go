package arith

import (
	"github.com/cronokirby/safenum"
)

// Modulus wraps a safenum.Modulus and enables faster modular exponentiation when
// the factorization is known.
// When n = p⋅q, xᵉ (mod n) can be computed with only two exponentiations
// with p and q respectively.
type Modulus struct {
	// represents modulus n
	*safenum.Modulus
	// n = p⋅p
	p, q *safenum.Modulus
	// pInv = p⁻¹ (mod q)
	pNat, pInv *safenum.Nat
}

// ModulusFromN creates a simple wrapper around a given modulus n.
// The modulus is not copied.
func ModulusFromN(n *safenum.Modulus) *Modulus {
	return &Modulus{
		Modulus: n,
	}
}

// ModulusFromFactors creates the necessary cached values to accelerate
// exponentiation mod n.
func ModulusFromFactors(p, q *safenum.Nat) *Modulus {
	nNat := new(safenum.Nat).Mul(p, q, -1)
	nMod := safenum.ModulusFromNat(nNat)
	pMod := safenum.ModulusFromNat(p)
	qMod := safenum.ModulusFromNat(q)
	pInvQ := new(safenum.Nat).ModInverse(p, qMod)
	pNat := new(safenum.Nat).SetNat(p)
	return &Modulus{
		Modulus: nMod,
		p:       pMod,
		q:       qMod,
		pNat:    pNat,
		pInv:    pInvQ,
	}
}

// Exp is equivalent to (safenum.Nat).Exp(x, e, n.Modulus).
// It returns xᵉ (mod n).
func (n *Modulus) Exp(x, e *safenum.Nat) *safenum.Nat {
	if n.hasFactorization() {
		var xp, xq safenum.Nat
		xp.Exp(x, e, n.p) // x₁ = xᵉ (mod p₁)
		xq.Exp(x, e, n.q) // x₂ = xᵉ (mod p₂)
		// r = x₁ + p₁ ⋅ [p₁⁻¹ (mod p₂)] ⋅ [x₁ - x₂] (mod n)
		r := xq.ModSub(&xq, &xp, n.Modulus)
		r.ModMul(r, n.pInv, n.Modulus)
		r.ModMul(r, n.pNat, n.Modulus)
		r.ModAdd(r, &xp, n.Modulus)
		return r
	}
	return new(safenum.Nat).Exp(x, e, n.Modulus)
}

// ExpI is equivalent to (safenum.Nat).ExpI(x, e, n.Modulus).
// It returns xᵉ (mod n).
func (n *Modulus) ExpI(x *safenum.Nat, e *safenum.Int) *safenum.Nat {
	if n.hasFactorization() {
		y := n.Exp(x, e.Abs())
		inverted := new(safenum.Nat).ModInverse(y, n.Modulus)
		y.CondAssign(e.IsNegative(), inverted)
		return y
	}
	return new(safenum.Nat).ExpI(x, e, n.Modulus)
}

func (n Modulus) hasFactorization() bool {
	return n.p != nil && n.q != nil && n.pNat != nil && n.pInv != nil
}
