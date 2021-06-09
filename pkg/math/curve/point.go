package curve

import (
	"crypto/ecdsa"
	"errors"
	"io"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

type Point struct {
	x big.Int
	y big.Int
}

// Bytes returns an uncompressed point encoding of v.
// Returns nil if v == Identity
func (v *Point) Bytes() []byte {
	if v.IsIdentity() {
		return nil
	}
	ret := make([]byte, 1+2*ByteSize)

	ret[0] = 4 // uncompressed point
	v.x.FillBytes(ret[1 : 1+ByteSize])
	v.y.FillBytes(ret[1+ByteSize : 1+2*ByteSize])

	return ret
}

// BytesCompressed returns a compressed point encoding of v.
// Returns nil if v == Identity
func (v *Point) BytesCompressed() []byte {
	if v.IsIdentity() {
		return nil
	}
	compressed := make([]byte, 1+ByteSize)
	compressed[0] = byte(v.y.Bit(0)) | 2

	v.x.FillBytes(compressed[1:])

	return compressed
}

// Set sets v = u, and returns v.
func (v *Point) Set(u *Point) *Point {
	v.x.Set(&u.x)
	v.y.Set(&u.y)
	return v
}

func (v *Point) SetPublicKey(pk *ecdsa.PublicKey) *Point {
	v.x.Set(pk.X)
	v.y.Set(pk.Y)
	return v
}

// SetBytes deserializes a point in uncompressed form.
func (v *Point) SetBytes(x []byte) (*Point, error) {
	if len(x) == 0 {
		v.x.SetInt64(0)
		v.y.SetInt64(0)
		return v, nil
	}
	if len(x) != 1+2*ByteSize {
		return nil, errors.New("point: wrong input length")
	}
	if x[0] != 4 { // uncompressed form
		return nil, errors.New("point: uncompressed bit not set")
	}
	v.x.SetBytes(x[1 : 1+ByteSize])
	v.y.SetBytes(x[1+ByteSize:])
	if v.x.Cmp(P) >= 0 || v.y.Cmp(P) >= 0 {
		return nil, errors.New("point: coordinate was not reduced")
	}
	if !Curve.IsOnCurve(&v.x, &v.y) {
		return nil, errors.New("point: not on curve")
	}
	return v, nil
}

// Add sets v = p + Q, and returns v.
func (v *Point) Add(p, q *Point) *Point {
	return v.setCoords(Curve.Add(&p.x, &p.y, &q.x, &q.y))
}

// Subtract sets v = p - Q, and returns v.
func (v *Point) Subtract(p, q *Point) *Point {
	var qYNeg big.Int
	qYNeg.Neg(&p.y)
	qYNeg.Mod(&qYNeg, P)
	return v.setCoords(Curve.Add(&p.x, &p.y, &q.x, &qYNeg))
}

// Negate sets v = -p, and returns v.
func (v *Point) Negate(p *Point) *Point {
	v.x.Set(&p.x)
	v.y.Neg(&p.y)
	v.y.Mod(&v.y, P)
	return v
}

// Equal returns 1 if v is equivalent to u, and 0 otherwise.
func (v *Point) Equal(u *Point) bool {
	if v.x.Cmp(&u.x) == 0 && v.y.Cmp(&u.y) == 0 {
		return true
	}
	return false
}

// ScalarBaseMult sets v = x * B, where B is the canonical generator, and
// returns v.
//
// The scalar multiplication is done in constant time.
func (v *Point) ScalarBaseMult(x *Scalar) *Point {
	return v.setCoords(Curve.ScalarBaseMult(x.Bytes()))
}

// ScalarMult sets v = x * q, and returns v.
//
// The scalar multiplication is done in constant time.
func (v *Point) ScalarMult(x *Scalar, q *Point) *Point {
	return v.setCoords(Curve.ScalarMult(&q.x, &q.y, x.Bytes()))
}

// NewBasePoint returns a point with both coordinates set to 0.
func NewBasePoint() *Point {
	var p Point
	p.x.Set(Curve.Gx)
	p.y.Set(Curve.Gy)
	return &p
}

// NewIdentityPoint returns a point with both coordinates set to 0.
func NewIdentityPoint() *Point {
	return &Point{}
}

func (v *Point) setCoords(x, y *big.Int) *Point {
	v.x.Set(x)
	v.y.Set(y)
	return v
}

// IsIdentity returns true if the point is ∞
func (v *Point) IsIdentity() bool {
	return v.x.Sign() == 0 && v.y.Sign() == 0
}

// ToPublicKey returns an "official" ECDSA public key
func (v *Point) ToPublicKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: Curve,
		X:     &v.x,
		Y:     &v.y,
	}
}

// XScalar returns the x coordinate of v as a scalar mod q
func (v *Point) XScalar() *Scalar {
	var s Scalar
	s.SetBigInt(&v.x)

	return &s
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
// It writes the full uncompressed point to w, ie 64 bytes
func (v *Point) WriteTo(w io.Writer) (int64, error) {
	nAll := int64(0)
	buf := make([]byte, params.BytesScalar)

	v.x.FillBytes(buf)
	n, err := w.Write(buf)
	nAll += int64(n)
	if err != nil {
		return nAll, err
	}

	v.y.FillBytes(buf)
	n, err = w.Write(buf)
	nAll += int64(n)
	return nAll, err
}
