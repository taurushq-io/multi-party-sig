package pb

import (
	"errors"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
)

// Unmarshal checks whether the Int is valid and returns an appropriate big.Int.
// (Signs are preserved)
func (x *Int) Unmarshal() *big.Int {
	var n big.Int
	_ = n.GobDecode(x.Int)
	return &n
}

func NewInt(n *big.Int) *Int {
	b, _ := n.GobEncode()
	return &Int{
		Int: b,
	}
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

func NewCiphertext(c *paillier.Ciphertext) *Ciphertext {
	return &Ciphertext{
		C: NewInt(c.Int()),
	}
}

func (x *Ciphertext) Unmarshal() *paillier.Ciphertext {
	var c paillier.Ciphertext
	n := x.C.Unmarshal()
	c.SetInt(n)
	return &c
}
