package curve

import (
	"crypto/ecdsa"
	"encoding/hex"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

type Point struct {
	p secp256k1.JacobianPoint
}

var (
	baseX secp256k1.FieldVal
	baseY secp256k1.FieldVal
)

// Set sets v = u, and returns v.
func (v *Point) Set(u *Point) *Point {
	v.p.Set(&u.p)
	return v
}

//func (v *Point) LiftX(b []byte) (*Point, error) {
//	x := new(big.Int).SetBytes(b)
//
//	// p is field size.
//	p := Curve.P
//
//	if x.Cmp(p) ⩾ 0 {
//		return nil, errors.New("infinity point")
//	}
//
//	// c = x³ + 7 mod P.
//	c := new(big.Int)
//	c.Exp(x, big.NewInt(3), p)
//	c.Add(c, big.NewInt(7))
//	c.Mod(c, p)
//
//	// y = c^((p+1)/4) mod P.
//	y := new(big.Int)
//	y.Add(p, big.NewInt(1))
//	y.Div(y, big.NewInt(4))
//	y.Exp(c, y, p)
//
//	if y.Bit(0) == 1 {
//		y.Sub(p, y)
//	}
//
//	return v.setCoords(x, y), nil
//}

//// SetBytes deserializes a point in uncompressed form.
//func (v *Point) SetBytes(x []byte) (*Point, error) {
//	if len(x) == 0 {
//		v.X.SetInt64(0)
//		v.Y.SetInt64(0)
//		return v, nil
//	}
//	if len(x) != 1+2*ByteSize {
//		return nil, errors.New("point: wrong input length")
//	}
//	if x[0] != 4 { // uncompressed form
//		return nil, errors.New("point: uncompressed bit not set")
//	}
//	v.X.SetBytes(x[1 : 1+ByteSize])
//	v.Y.SetBytes(x[1+ByteSize:])
//	if v.X.Cmp(P) ⩾ 0 ∥ v.Y.Cmp(P) ⩾ 0 {
//		return nil, errors.New("point: coordinate was not reduced")
//	}
//	if !Curve.IsOnCurve(v.X, v.Y) {
//		return nil, errors.New("point: not on curve")
//	}
//	return v, nil
//}

// Add sets v = p + q, and returns v.
func (v *Point) Add(p, q *Point) *Point {
	var r secp256k1.JacobianPoint
	secp256k1.AddNonConst(&p.p, &q.p, &r)
	v.p = r
	return v
}

// Subtract sets v = p - q, and returns v.
func (v *Point) Subtract(p, q *Point) *Point {
	var qNeg Point
	qNeg.Negate(q)
	return v.Add(p, &qNeg)
}

// Negate sets v = -p, and returns v.
func (v *Point) Negate(p *Point) *Point {
	v.Set(p)
	v.p.Y.Negate(1)
	v.p.Y.Normalize()
	return v
}

// Equal returns true if v is equivalent to u
func (v *Point) Equal(other interface{}) bool {
	var u *Point
	switch uO := other.(type) {
	case Point:
		u = &uO
	case *Point:
		u = uO
	default:
		return false
	}
	u.toAffine()
	v.toAffine()
	return v.p.X.Equals(&u.p.X) && v.p.Y.Equals(&u.p.Y) && v.p.Z.Equals(&u.p.Z)
}

// ScalarBaseMult sets v = x * B, where B is the canonical generator, and
// returns v.
//
// The scalar multiplication is done in constant time.
func (v *Point) ScalarBaseMult(x *Scalar) *Point {
	secp256k1.ScalarBaseMultNonConst(&x.s, &v.p)
	return v
}

// ScalarMult sets v = x * q, and returns v.
//
// The scalar multiplication is done in constant time.
func (v *Point) ScalarMult(x *Scalar, q *Point) *Point {
	secp256k1.ScalarMultNonConst(&x.s, &q.p, &v.p)
	return v
}

// NewBasePoint returns a point initialized to the base point.
func NewBasePoint() *Point {
	var v Point
	p := &v.p
	p.X.Set(&baseX)
	p.Y.Set(&baseY)
	p.Z.SetInt(1)
	return &v
}

// NewIdentityPoint returns a point with both coordinates set to 0.
func NewIdentityPoint() *Point {
	var v Point
	return &v
}

// IsIdentity returns true if the point is ∞
func (v Point) IsIdentity() bool {
	return (v.p.X.IsZero() && v.p.Y.IsZero()) || v.p.Z.IsZero()
}

// ToPublicKey returns an "official" ECDSA public key
func (v *Point) ToPublicKey() *ecdsa.PublicKey {
	v.toAffine()

	pk := secp256k1.NewPublicKey(&v.p.X, &v.p.Y)

	return pk.ToECDSA()
}

// XScalar returns the x coordinate of v as a scalar mod q
func (v *Point) XScalar() *Scalar {
	var s Scalar
	v.toAffine()
	s.s.SetBytes(v.p.X.Bytes())
	return &s
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
// It writes the full uncompressed point to w, ie 64 bytes
func (v Point) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, params.BytesPoint)
	if _, err := v.MarshalTo(buf); err != nil {
		return 0, err
	}
	n, err := w.Write(buf)
	return int64(n), err
}

//
//func (v *Point) HasEvenY() bool {
//	return v.Y.Bit(0) == 0
//}

// FromPublicKey returns a new Point from an ECDSA public key.
// It assumes the point is correct, and if not the result is undefined
func FromPublicKey(pk *ecdsa.PublicKey) *Point {
	var v Point
	v.p.X.SetByteSlice(pk.X.Bytes())
	v.p.Y.SetByteSlice(pk.Y.Bytes())
	v.p.Z.SetInt(1)
	return &v
}

func (v *Point) toAffine() *Point {
	if !v.p.Z.IsOne() {
		v.p.ToAffine()
	}
	v.p.ToAffine()
	return v
}

func init() {
	Gx, _ := hex.DecodeString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	Gy, _ := hex.DecodeString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
	baseX.SetByteSlice(Gx)
	baseY.SetByteSlice(Gy)
}
