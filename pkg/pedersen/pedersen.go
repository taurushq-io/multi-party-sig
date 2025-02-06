package pedersen

import (
	"fmt"
	"io"

	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"
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
	n    *arith.Modulus
	s, t *saferith.Nat
}

// New returns a new set of Pedersen parameters.
// Assumes ValidateParameters(n, s, t) returns nil.
func New(n *arith.Modulus, s, t *saferith.Nat) *Parameters {
	return &Parameters{
		s: s,
		t: t,
		n: n,
	}
}

// ValidateParameters check n, s and t, and returns an error if any of the following is true:
// - n, s, or t is nil.
// - s, t are not in [1, …,n-1].
// - s, t are not coprime to N.
// - s = t.
func ValidateParameters(n *saferith.Modulus, s, t *saferith.Nat) error {
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
func (p Parameters) N() *saferith.Modulus { return p.n.Modulus }

// N, but as an arith modulus, which is sometimes useful
func (p Parameters) NArith() *arith.Modulus { return p.n }

// S = r² mod N.
func (p Parameters) S() *saferith.Nat { return p.s }

// T = Sˡ mod N.
func (p Parameters) T() *saferith.Nat { return p.t }

// Commit computes sˣ tʸ (mod N)
//
// x and y are taken as saferith.Int, because we want to keep these values in secret,
// in general. The commitment produced, on the other hand, hides their values,
// and can be safely shared.
func (p Parameters) Commit(x, y *saferith.Int) *saferith.Nat {
	sx := p.n.ExpI(p.s, x)
	ty := p.n.ExpI(p.t, y)

	result := sx.ModMul(sx, ty, p.n.Modulus)

	return result
}

// Verify returns true if sᵃ tᵇ ≡ S Tᵉ (mod N).
func (p Parameters) Verify(a, b, e *saferith.Int, S, T *saferith.Nat) bool {
	if a == nil || b == nil || S == nil || T == nil || e == nil {
		return false
	}
	nMod := p.n.Modulus
	if !arith.IsValidNatModN(nMod, S, T) {
		return false
	}

	sa := p.n.ExpI(p.s, a)         // sᵃ (mod N)
	tb := p.n.ExpI(p.t, b)         // tᵇ (mod N)
	lhs := sa.ModMul(sa, tb, nMod) // lhs = sᵃ⋅tᵇ (mod N)

	te := p.n.ExpI(T, e)          // Tᵉ (mod N)
	rhs := te.ModMul(te, S, nMod) // rhs = S⋅Tᵉ (mod N)
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
	for _, i := range []*saferith.Nat{p.n.Nat(), p.s, p.t} {
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

func (p *Parameters) MarshalBinary() ([]byte, error) {
	tmp := [3][]byte{p.n.Bytes(), p.s.Bytes(), p.t.Bytes()}
	return cbor.Marshal(tmp)
}

func (p *Parameters) UnmarshalBinary(data []byte) error {
	var tmp [3][]byte
	err := cbor.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	p.n = arith.ModulusFromN(saferith.ModulusFromBytes(tmp[0]))
	p.s = new(saferith.Nat).SetBytes(tmp[1])
	p.t = new(saferith.Nat).SetBytes(tmp[2])
	return nil
}
