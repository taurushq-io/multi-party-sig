package pedersen

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
)

type Parameters struct {
	N *big.Int // N = p•q, p ≡ q ≡ 3 mod 4
	S *big.Int // S = r² mod N
	T *big.Int // T = Sˡ mod N
}

func (p *Parameters) IsValid() bool {
	// S, T < N
	if p.S.Cmp(p.N) != -1 || p.T.Cmp(p.N) != -1 {
		return false
	}

	// S, T > 0
	if p.S.Sign() != 1 || p.T.Sign() != 1 {
		return false
	}

	// S, T != 1
	one := big.NewInt(1)
	if p.S.Cmp(one) == 0 || p.T.Cmp(one) == 0 {
		return false
	}

	// gcd(S, N) == gcd(T, N) == 1
	if !arith.IsCoprime(p.S, p.N) || !arith.IsCoprime(p.T, p.N) {
		return false
	}

	if p.S.Cmp(p.T) == 0 {
		return false
	}
	return true
}

// Commit computes sˣ tʸ (mod N)
func (p *Parameters) Commit(a, b *big.Int) *big.Int {
	result, tmp := bigint(), bigint()

	result.Exp(p.S, a, p.N)
	tmp.Exp(p.T, b, p.N)
	result.Mul(result, tmp)
	result.Mod(result, p.N)
	return result
}

// Verify returns true if sᵃ tᵇ ≡ S Tᵉ (mod N)
func (p *Parameters) Verify(a, b, S, T, e *big.Int) bool {
	lhs, rhs := bigint(), bigint()

	lhs.Exp(p.S, a, p.N) // lhs = sᵃ (mod N)
	rhs.Exp(p.T, b, p.N) // rhs = tᵇ (mod N)
	lhs.Mul(lhs, rhs)    // lhs *= rhs
	lhs.Mod(lhs, p.N)    // lhs = lhs (mod N)

	rhs.Exp(T, e, p.N) // rhs = Tᵉ (mod N)
	rhs.Mul(rhs, S)    // rhs *= S
	rhs.Mod(rhs, p.N)  // rhs = rhs (mod N)
	return lhs.Cmp(rhs) == 0
}

func bigint() *big.Int {
	var x big.Int
	buf := make([]big.Word, 0, 68)
	x.SetBits(buf)
	return &x
}
