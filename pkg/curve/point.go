package curve

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

type Point struct {
	x big.Int
	y big.Int
}

func (v *Point) Bytes() []byte {
	return elliptic.Marshal(Curve, &v.x, &v.y)
}

// Set sets v = u, and returns v.
func (v *Point) Set(u *Point) *Point {
	v.x.Set(&u.x)
	v.y.Set(&u.y)
	return v
}

//
func (v *Point) SetBytes(x []byte) (*Point, error) {
	xNew, yNew := elliptic.Unmarshal(Curve, x)
	if xNew == nil {
		return nil, errors.New("curve: failed to decompress bytes")
	}
	v.x.Set(xNew)
	v.y.Set(yNew)
	return v, nil
}

// Add sets v = p + Q, and returns v.
func (v *Point) Add(p, q *Point) *Point {
	xNew, yNew := Curve.Add(&p.x, &p.y, &q.x, &q.y)
	v.x.Set(xNew)
	v.y.Set(yNew)
	return v
}

// Subtract sets v = p - Q, and returns v.
func (v *Point) Subtract(p, q *Point) *Point {
	var qNeg Point
	qNeg.Negate(q)
	xNew, yNew := Curve.Add(&p.x, &p.y, &qNeg.x, &qNeg.y)
	v.x.Set(xNew)
	v.y.Set(yNew)
	return v
}

// Negate sets v = -p, and returns v.
func (v *Point) Negate(p *Point) *Point {
	v.x.Set(&p.x)
	v.y.Neg(&p.y)
	v.y.Mod(&v.y, Curve.Params().N)
	return v
}

// Equal returns 1 if v is equivalent to u, and 0 otherwise.
func (v *Point) Equal(u *Point) int {
	if v.x.Cmp(&u.x) == 0 && v.y.Cmp(&u.y) == 0 {
		return 1
	}
	return 0
}

// ScalarBaseMult sets v = x * B, where B is the canonical generator, and
// returns v.
//
// The scalar multiplication is done in constant time.
func (v *Point) ScalarBaseMult(x *Scalar) *Point {
	xNew, yNew := Curve.ScalarBaseMult(x.Bytes())
	v.x.Set(xNew)
	v.y.Set(yNew)
	return v
}

// ScalarMult sets v = x * q, and returns v.
//
// The scalar multiplication is done in constant time.
func (v *Point) ScalarMult(x *Scalar, q *Point) *Point {
	var xNew, yNew *big.Int
	xNew, yNew = Curve.ScalarMult(&q.x, &q.y, x.Bytes())
	v.x.Set(xNew)
	v.y.Set(yNew)
	return v
}

func NewIdentityPoint() *Point {
	var v Point
	v.x.SetInt64(0)
	v.y.SetInt64(0)
	return &v
}
