package pedersen

import (
	"math/big"
)

type Parameters struct {
	N, S, T *big.Int
}

// Commit computes sˣ tʸ (mod N)
func (p *Parameters) Commit(a, b *big.Int) *big.Int {
	var result, tmp big.Int

	result.Exp(p.S, a, p.N)
	tmp.Exp(p.T, b, p.N)
	result.Mul(&result, &tmp)
	result.Mod(&result, p.N)
	return &result
}

// Verify returns true if sᵃ tᵇ ≡ S Tᵉ (mod N)
func (p *Parameters) Verify(a, b, S, T, e *big.Int) bool {
	var lhs, rhs big.Int

	lhs.Exp(p.S, a, p.N) // lhs = sᵃ (mod N)
	rhs.Exp(p.T, b, p.N) // rhs = tᵇ (mod N)
	lhs.Mul(&lhs, &rhs)  // lhs *= rhs
	lhs.Mod(&lhs, p.N)   // lhs = lhs (mod N)

	rhs.Exp(T, e, p.N) // rhs = Tᵉ (mod N)
	rhs.Mul(&rhs, S)   // rhs *= S
	rhs.Mod(&rhs, p.N) // rhs = rhs (mod N)

	return lhs.Cmp(&rhs) == 0
}
