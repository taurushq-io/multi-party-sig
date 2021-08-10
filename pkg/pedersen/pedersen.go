package pedersen

import (
	"fmt"
	"io"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
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
	n    *safenum.Modulus
	s, t *safenum.Nat
}

// New returns a new set of Pedersen parameters.
// Assumes ValidateParameters(n, s, t) returns nil.
func New(n *safenum.Modulus, s, t *safenum.Nat) *Parameters {
	return &Parameters{
		n: n,
		s: s,
		t: t,
	}
}

// ValidateParameters check n, s and t, and returns an error if any of the following is true:
// - n, s, or t is nil.
// - s, t are not in [1, …,n-1].
// - s, t are not coprime to N.
// - s = t.
func ValidateParameters(n *safenum.Modulus, s, t *safenum.Nat) error {
	if n == nil || s == nil || t == nil {
		return ErrNilFields
	}
	// s, t ∈ ℤₙˣ
	if !arith.IsValidNatModN(n, s, t) {
		return ErrNotValidModN
	}
	// s ≡ t
	if _, eq, _ := s.Cmp(t); eq == 1 {
		return ErrSEqualT
	}
	return nil
}

// N = p•q, p ≡ q ≡ 3 mod 4.
func (p Parameters) N() *safenum.Modulus { return p.n }

// S = r² mod N.
func (p Parameters) S() *safenum.Nat { return p.s }

// T = Sˡ mod N.
func (p Parameters) T() *safenum.Nat { return p.t }

// Commit computes sˣ tʸ (mod N)
//
// x and y are taken as safenum.Int, because we want to keep these values in secret,
// in general. The commitment produced, on the other hand, hides their values,
// and can be safely shared. This is why we produce a big.Int instead.
func (p Parameters) Commit(x, y *safenum.Int) *safenum.Nat {
	sx := new(safenum.Nat).ExpI(p.s, x, p.n)
	ty := new(safenum.Nat).ExpI(p.t, y, p.n)

	result := sx.ModMul(sx, ty, p.n)

	return result
}

// Verify returns true if sᵃ tᵇ ≡ S Tᵉ (mod N).
func (p Parameters) Verify(a, b, e *safenum.Int, S, T *safenum.Nat) bool {
	if a == nil || b == nil || S == nil || T == nil || e == nil {
		return false
	}
	if !arith.IsValidNatModN(p.n, S, T) {
		return false
	}

	lhs, rhs := new(safenum.Nat), new(safenum.Nat)

	lhs.ExpI(p.s, a, p.n)     // lhs = sᵃ (mod N)
	rhs.ExpI(p.t, b, p.n)     // rhs = tᵇ (mod N)
	lhs.ModMul(lhs, rhs, p.n) // lhs *= rhs (mod N)

	rhs.ExpI(T, e, p.n)     // rhs = Tᵉ (mod N)
	rhs.ModMul(rhs, S, p.n) // rhs *= S (mod N)
	return lhs.Eq(rhs) == 1
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (p *Parameters) WriteTo(w io.Writer) (int64, error) {
	if p == nil {
		return 0, io.ErrUnexpectedEOF
	}
	nAll := int64(0)
	buf := make([]byte, params.BytesIntModN)

	// write N, S, T
	for _, i := range []*safenum.Nat{p.n.Nat(), p.s, p.t} {
		i.FillBytes(buf)
		n, err := w.Write(buf)
		nAll += int64(n)
		if err != nil {
			return nAll, err
		}
	}
	return nAll, nil
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (Parameters) Domain() string {
	return "Pedersen Parameters"
}
