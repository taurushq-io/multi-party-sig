package pedersen

import (
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

func (p *Parameters) Validate() error {
	if p == nil || p.N == nil || p.S == nil || p.T == nil {
		return errors.New("pedersen.Parameters: contains nil field")
	}

	one := big.NewInt(1)
	gcd := big.NewInt(1)

	ints := []*big.Int{p.S, p.T}
	names := []string{"S", "T"}
	for i := 0; i < 2; i++ {

		s := ints[i]
		id := names[i]

		// s < N
		if s.Cmp(p.N) != -1 {
			return fmt.Errorf("pedersen.Parameters: %s is >= N", id)
		}

		// s ⩾ 1
		if s.Cmp(one) != 1 {
			return fmt.Errorf("pedersen.Parameters: %s < 1", id)
		}

		// gcd(s,N) == 1
		if gcd.GCD(nil, nil, s, p.N).Cmp(one) != 0 {
			return fmt.Errorf("pedersen.Parameters: gcd(%s, N) ≠ 1", id)
		}
	}

	if p.S.Cmp(p.T) == 0 {
		return errors.New("pedersen.Parameters: S == T")
	}
	return nil
}

// Commit computes sˣ tʸ (mod N)
func (p Parameters) Commit(x, y *big.Int) *big.Int {
	result, tmp := bigint(), bigint()

	result.Exp(p.S, x, p.N)
	tmp.Exp(p.T, y, p.N)
	result.Mul(result, tmp)
	result.Mod(result, p.N)
	return result
}

// Verify returns true if sᵃ tᵇ ≡ S Tᵉ (mod N)
func (p Parameters) Verify(a, b, S, T, e *big.Int) bool {
	if a == nil || b == nil || S == nil || T == nil || e == nil {
		return false
	}
	if !arith.IsValidModN(p.N, S, T) {
		return false
	}

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

func (p Parameters) Clone() *Parameters {
	var n, s, t big.Int
	return &Parameters{
		N: n.Set(p.N),
		S: s.Set(p.S),
		T: t.Set(p.T),
	}
}

func (p Parameters) Equal(o *Parameters) bool {
	return p.N.Cmp(o.N) == 0 && p.S.Cmp(o.S) == 0 && p.T.Cmp(o.T) == 0
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (p Parameters) WriteTo(w io.Writer) (int64, error) {
	nAll := int64(0)
	buf := make([]byte, params.BytesIntModN)

	// write N
	p.N.FillBytes(buf)
	n, err := w.Write(buf)
	nAll += int64(n)
	if err != nil {
		return nAll, err
	}

	// write signs
	signs := byte(0)
	if p.S.Sign() == -1 {
		signs |= 1
	}
	if p.T.Sign() == -1 {
		signs |= 2
	}
	n, err = w.Write([]byte{signs})
	nAll += int64(n)
	if err != nil {
		return nAll, err
	}

	// write S
	p.S.FillBytes(buf)
	n, err = w.Write(buf)
	nAll += int64(n)
	if err != nil {
		return nAll, err
	}

	// write T
	p.T.FillBytes(buf)
	n, err = w.Write(buf)
	nAll += int64(n)
	return nAll, err
}
