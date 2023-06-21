package arith

import (
	"github.com/cronokirby/saferith"
)

// Modulus wraps a saferith.Modulus and enables faster modular exponentiation when
// the factorization is known.
// When n = p⋅q, xᵉ (mod n) can be computed with only two exponentiations
// with p and q respectively.
type Modulus struct {
	// represents modulus n
	*saferith.Modulus
	// n = p⋅p
	p, q *saferith.Modulus
	// pInv = p⁻¹ (mod q)
	pNat, pInv *saferith.Nat
}

// ModulusFromN creates a simple wrapper around a given modulus n.
// The modulus is not copied.
func ModulusFromN(n *saferith.Modulus) *Modulus {
	return &Modulus{
		Modulus: n,
	}
}

// ModulusFromFactors creates the necessary cached values to accelerate
// exponentiation mod n.
func ModulusFromFactors(p, q *saferith.Nat) *Modulus {
	nNat := new(saferith.Nat).Mul(p, q, -1)
	nMod := saferith.ModulusFromNat(nNat)
	pMod := saferith.ModulusFromNat(p)
	qMod := saferith.ModulusFromNat(q)
	pInvQ := new(saferith.Nat).ModInverse(p, qMod)
	pNat := new(saferith.Nat).SetNat(p)
	return &Modulus{
		Modulus: nMod,
		p:       pMod,
		q:       qMod,
		pNat:    pNat,
		pInv:    pInvQ,
	}
}

// Exp is equivalent to (saferith.Nat).Exp(x, e, n.Modulus).
// It returns xᵉ (mod n).
func (n *Modulus) Exp(x, e *saferith.Nat) *saferith.Nat {
	if n.hasFactorization() {
		var xp, xq saferith.Nat
		xp.Exp(x, e, n.p) // x₁ = xᵉ (mod p₁)
		xq.Exp(x, e, n.q) // x₂ = xᵉ (mod p₂)
		// r = x₁ + p₁ ⋅ [p₁⁻¹ (mod p₂)] ⋅ [x₁ - x₂] (mod n)
		r := xq.ModSub(&xq, &xp, n.Modulus)
		r.ModMul(r, n.pInv, n.Modulus)
		r.ModMul(r, n.pNat, n.Modulus)
		r.ModAdd(r, &xp, n.Modulus)
		return r
	}
	return new(saferith.Nat).Exp(x, e, n.Modulus)
}

// ExpI is equivalent to (saferith.Nat).ExpI(x, e, n.Modulus).
// It returns xᵉ (mod n).
func (n *Modulus) ExpI(x *saferith.Nat, e *saferith.Int) *saferith.Nat {
	if n.hasFactorization() {
		y := n.Exp(x, e.Abs())
		inverted := new(saferith.Nat).ModInverse(y, n.Modulus)
		y.CondAssign(e.IsNegative(), inverted)
		return y
	}
	return new(saferith.Nat).ExpI(x, e, n.Modulus)
}

func (n Modulus) hasFactorization() bool {
	return n.p != nil && n.q != nil && n.pNat != nil && n.pInv != nil
}
