package secp256k1

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var curve = secp256k1.S256()

type Point struct {
	x big.Int
	y big.Int
}

func (v *Point) Bytes() []byte {
	return curve.Marshal(&v.x, &v.y)
}

// Set sets v = u, and returns v.
func (v *Point) Set(u *Point) *Point {
	v.x.Set(&u.x)
	v.y.Set(&u.y)
	return v
}

//
func (v *Point) SetBytes(x []byte) (*Point, error) {
	var xNew, yNew *big.Int
	xNew, yNew = curve.Unmarshal(x)
	if xNew == nil {
		return nil, errors.New("secp256k1: failed to decompress bytes")
	}
	v.x.Set(xNew)
	v.y.Set(yNew)
	return v, nil
}

// Add sets v = p + Q, and returns v.
func (v *Point) Add(p, q *Point) *Point {
	var xNew, yNew *big.Int
	xNew, yNew = curve.Add(&p.x, &p.y, &q.x, &q.y)
	v.x.Set(xNew)
	v.y.Set(yNew)
	return v
}

// Subtract sets v = p - Q, and returns v.
func (v *Point) Subtract(p, q *Point) *Point {
	var xNew, yNew *big.Int
	var qNeg Point
	qNeg.Negate(q)
	xNew, yNew = curve.Add(&p.x, &p.y, &qNeg.x, &qNeg.y)
	v.x.Set(xNew)
	v.y.Set(yNew)
	return v
}

// Negate sets v = -p, and returns v.
func (v *Point) Negate(p *Point) *Point {
	v.x.Set(&p.x)
	v.y.Neg(&p.y)
	v.y.Mod(&v.y, curve.N)
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
func (v *Point) ScalarBaseMult(x *Scalar) *Point{
	var xNew, yNew *big.Int
	xNew, yNew = curve.ScalarBaseMult(x.Bytes())
	v.x.Set(xNew)
	v.y.Set(yNew)
	return v
}

// ScalarMult sets v = x * q, and returns v.
//
// The scalar multiplication is done in constant time.
func (v *Point) ScalarMult(x *Scalar, q *Point) *Point {
	var xNew, yNew *big.Int
	xNew, yNew = curve.ScalarMult(&q.x, &q.y, x.Bytes())
	v.x.Set(xNew)
	v.y.Set(yNew)
	return v
}