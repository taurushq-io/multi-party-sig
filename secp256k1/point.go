package secp256k1

import (
	"errors"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"
)

var curve = secp256k1.S256()

type Point struct {
	x, y big.Int

	// Make the type not comparable with bradfitz's device, since equal points
	// can be represented by different Go values.
	_ [0]func()
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

// Add sets v = p + q, and returns v.
func (v *Point) Add(p, q *Point) *Point {
	var xNew, yNew *big.Int
	xNew, yNew = curve.Add(&p.x, &p.y, &q.x, &q.y)
	v.x.Set(xNew)
	v.y.Set(yNew)
	return v
}

// Subtract sets v = p - q, and returns v.
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
