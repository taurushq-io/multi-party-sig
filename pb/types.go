package pb

import (
	"errors"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
)

// Unmarshal checks whether the Int is valid and returns an appropriate big.Int.
// (Signs are preserved)
func (x *Int) Unmarshal() (*big.Int, error) {
	var n big.Int
	b := x.GetInt()
	if b == nil {
		if x.GetZero() {
			return &n, nil
		}
		return nil, errors.New("pb.Int: Unmarshal: got nil int")
	}
	n.SetBytes(b)
	if x.GetNeg() {
		n.Neg(&n)
	}
	return &n, nil
}

// IsValid checks whether Int is nil and a valid 0.
func (x *Int) IsValid() bool {
	if x == nil {
		return false
	}
	if len(x.Int) == 0 && !x.Zero {
		return false
	}
	return true
}

func NewInt(n *big.Int) *Int {
	switch n.Sign() {
	case -1:
		return &Int{
			Int:  n.Bytes(),
			Zero: false,
			Neg:  true,
		}
	case 0:
		return &Int{
			Int:  nil,
			Zero: true,
			Neg:  false,
		}
	case 1:
		return &Int{
			Int:  n.Bytes(),
			Zero: false,
			Neg:  false,
		}
	}
	return nil
}

func NewScalar(s *curve.Scalar) *Scalar {
	return &Scalar{
		Scalar: s.Bytes(),
	}
}

func (x *Scalar) Unmarshal() *curve.Scalar {
	var s curve.Scalar
	s.SetBytes(x.GetScalar())
	return &s
}

func NewPoint(v *curve.Point) *Point {
	if v.IsIdentity() {
		return &Point{
			Point:      nil,
			IsIdentity: true,
		}
	}
	return &Point{
		Point:      v.Bytes(),
		IsIdentity: false,
	}
}

func (x *Point) IsValid() bool {
	if x == nil {
		return false
	}
	if len(x.Point) == 0 {
		return x.IsIdentity
	}
	return true
}

func (x *Point) Unmarshal() (*curve.Point, error) {
	if !x.IsValid() {
		return nil, errors.New("proto: Point: invalid")
	}
	var p curve.Point
	if x.IsIdentity {
		return &p, nil
	}
	return p.SetBytes(x.Point)
}

func (x *Ciphertext) Unmarshal() (*paillier.Ciphertext, error) {
	var c paillier.Ciphertext
	n, err := x.C.Unmarshal()
	if err != nil {
		return nil, err
	}
	c.SetInt(n)
	return &c, nil
}
