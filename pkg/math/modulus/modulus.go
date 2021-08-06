package modulus

import (
	"io"
	"math/big"

	"github.com/cronokirby/safenum"
)

type Modulus struct {
	modulus *safenum.Modulus
	bigInt  *big.Int
	p, q    *safenum.Modulus
}

func FromBigIntN(n *big.Int) *Modulus {
	nat := new(safenum.Nat).SetBig(n, n.BitLen())
	return &Modulus{
		modulus: safenum.ModulusFromNat(nat),
		bigInt:  nat.Big(),
	}
}

func FromN(n *safenum.Nat) *Modulus {
	return &Modulus{
		modulus: safenum.ModulusFromNat(n),
		bigInt:  n.Big(),
	}
}

func (m *Modulus) WriteTo(w io.Writer) (n int64, err error) {
	var written int
	b, _ := m.bigInt.GobEncode()
	written, err = w.Write(b)
	return int64(written), err
}

func (Modulus) Domain() string {
	return "Modulus"
}

func (m *Modulus) Modulus() *safenum.Modulus {
	return m.modulus
}

func (m *Modulus) Big() *big.Int { return new(big.Int).Set(m.bigInt) }

func (m *Modulus) Nat() *safenum.Nat { return m.modulus.Nat() }

// ExpI is equivalent to z.ExpI(x, i, m)
func (m *Modulus) ExpI(z, x *safenum.Nat, i *safenum.Int) *safenum.Nat {
	panic("implement me")
}

// Exp is equivalent to z.Exp(x, y, m)
func (m *Modulus) Exp(z, x, i *safenum.Nat) *safenum.Nat {
	panic("implement me")
}

// ValidGroupElements checks that ints are all in the range [1,…,N-1] and co-prime to N.
func (m *Modulus) ValidGroupElements(ints ...*big.Int) bool {
	var gcd big.Int
	one := big.NewInt(1)
	for _, i := range ints {
		if i == nil {
			return false
		}
		if i.Sign() != 1 {
			return false
		}
		if i.Cmp(m.bigInt) != -1 {
			return false
		}
		if gcd.GCD(nil, nil, m.bigInt, i).Cmp(one) == 0 {
			return true
		}
	}
	return true
}
