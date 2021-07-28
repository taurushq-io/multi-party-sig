package pedersen

import (
	"fmt"
	"io"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

type Error string

const (
	ErrNilFields    Error = "contains nil field"
	ErrSEqualT      Error = "S cannot be equal to T"
	ErrNotValidModN Error = "S and T must be in [1,…,N-1] and coprime to N"
)

func (e Error) Error() string {
	return fmt.Sprintf("pedersen: %s", string(e))
}

type Parameters struct {
	n, s, t *big.Int
}

// New returns a new set of Pedersen parameters,
// It returns an error if any of the following is true:
// - n, s, or t is nil.
// - s, t are not in [1, …,n-1].
// - s, t are not coprime to N.
// - s = t.
func New(n, s, t *big.Int) (*Parameters, error) {
	if err := ValidateParameters(n, s, t); err != nil {
		return nil, err
	}
	return &Parameters{
		n: n,
		s: s,
		t: t,
	}, nil
}

func ValidateParameters(n, s, t *big.Int) error {
	if n == nil || s == nil || t == nil {
		return ErrNilFields
	}
	// s, t ∈ ℤₙˣ
	if !arith.IsValidModN(n, s, t) {
		return ErrNotValidModN
	}
	// s ≡ t
	if s.Cmp(t) == 0 {
		return ErrSEqualT
	}
	return nil
}

// N = p•q, p ≡ q ≡ 3 mod 4.
func (p Parameters) N() *big.Int { return p.n }

// S = r² mod N.
func (p Parameters) S() *big.Int { return p.s }

// T = Sˡ mod N.
func (p Parameters) T() *big.Int { return p.t }

// Commit computes sˣ tʸ (mod N)
//
// x and y are taken as safenum.Int, because we want to keep these values in secret,
// in general. The commitment produced, on the other hand, hides their values,
// and can be safely shared. This is why we produce a big.Int instead.
func (p Parameters) Commit(x, y *safenum.Int) *big.Int {
	sx := new(safenum.Nat).SetBig(p.s, p.s.BitLen())
	ty := new(safenum.Nat).SetBig(p.t, p.t.BitLen())
	nMod := safenum.ModulusFromNat(new(safenum.Nat).SetBig(p.n, p.n.BitLen()))

	sx.ExpI(sx, x, nMod)
	ty.ExpI(ty, y, nMod)

	result := sx.ModMul(sx, ty, nMod)

	return result.Big()
}

// Verify returns true if sᵃ tᵇ ≡ S Tᵉ (mod N).
func (p Parameters) Verify(a, b, S, T, e *big.Int) bool {
	if a == nil || b == nil || S == nil || T == nil || e == nil {
		return false
	}
	if !arith.IsValidModN(p.n, S, T) {
		return false
	}

	lhs, rhs := bigint(), bigint()

	lhs.Exp(p.s, a, p.n) // lhs = sᵃ (mod N)
	rhs.Exp(p.t, b, p.n) // rhs = tᵇ (mod N)
	lhs.Mul(lhs, rhs)    // lhs *= rhs
	lhs.Mod(lhs, p.n)    // lhs = lhs (mod N)

	rhs.Exp(T, e, p.n) // rhs = Tᵉ (mod N)
	rhs.Mul(rhs, S)    // rhs *= S
	rhs.Mod(rhs, p.n)  // rhs = rhs (mod N)
	return lhs.Cmp(rhs) == 0
}

func bigint() *big.Int {
	var x big.Int
	buf := make([]big.Word, 0, 68)
	x.SetBits(buf)
	return &x
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (p Parameters) WriteTo(w io.Writer) (int64, error) {
	nAll := int64(0)
	buf := make([]byte, params.BytesIntModN)

	// write N, S, T
	for _, i := range []*big.Int{p.n, p.s, p.t} {
		i.FillBytes(buf)
		n, err := w.Write(buf)
		nAll += int64(n)
		if err != nil {
			return nAll, err
		}
	}
	return nAll, nil
}

// Domain implements WriterToWithDomain, and separates this type within hash.Hash.
func (Parameters) Domain() string {
	return "Pedersen Parameters"
}
