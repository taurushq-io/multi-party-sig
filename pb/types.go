package pb

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
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
			Point: nil,
		}
	}
	return &Point{
		Point: v.Bytes(),
	}
}

func NewPointSlice(v []*curve.Point) []*Point {
	points := make([]*Point, len(v))
	for i, p := range v {
		points[i] = NewPoint(p)
	}
	return points
}

func UnmarshalPoints(ps []*Point) ([]*curve.Point, error) {
	var err error
	pts := make([]*curve.Point, len(ps))
	for i, p := range ps {
		pts[i], err = p.Unmarshal()
		if err != nil {
			return nil, err
		}
	}
	return pts, nil
}

func (x *Point) Unmarshal() (*curve.Point, error) {
	var p curve.Point
	if x.Point == nil {
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
	c := paillier.NewCiphertext()
	n := x.C.Unmarshal()
	c.SetInt(n)
	return c
}

func NewPolynomialExponent(p *polynomial.Exponent) *PolynomialExponent {
	return &PolynomialExponent{Coefficients: NewPointSlice(p.Coefficients())}
}

func (x *PolynomialExponent) Unmarshall() (*polynomial.Exponent, error) {
	var p polynomial.Exponent
	var err error
	points := make([]*curve.Point, len(x.Coefficients))
	for i := range points {
		points[i], err = x.Coefficients[i].Unmarshal()
		if err != nil {
			return nil, err
		}
	}
	return p.SetCoefficients(points), nil
}
