package curve

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/cronokirby/saferith"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var secp256k1BaseX, secp256k1BaseY secp256k1.FieldVal

func init() {
	Gx, _ := hex.DecodeString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	Gy, _ := hex.DecodeString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
	secp256k1BaseX.SetByteSlice(Gx)
	secp256k1BaseY.SetByteSlice(Gy)
}

type Secp256k1 struct{}

func (Secp256k1) NewPoint() Point {
	return new(Secp256k1Point)
}

func (Secp256k1) NewBasePoint() Point {
	out := new(Secp256k1Point)
	out.value.X.Set(&secp256k1BaseX)
	out.value.Y.Set(&secp256k1BaseY)
	out.value.Z.SetInt(1)
	return out
}

func (Secp256k1) NewScalar() Scalar {
	return new(Secp256k1Scalar)
}

func (Secp256k1) ScalarBits() int {
	return 256
}

func (Secp256k1) SafeScalarBytes() int {
	return 32
}

var secp256k1OrderNat, _ = new(saferith.Nat).SetHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
var secp256k1Order = saferith.ModulusFromNat(secp256k1OrderNat)

func (Secp256k1) Order() *saferith.Modulus {
	return secp256k1Order
}

func (Secp256k1) LiftX(data []byte) (*Secp256k1Point, error) {
	out := new(Secp256k1Point)
	out.value.Z.SetInt(1)
	if out.value.X.SetByteSlice(data) {
		return nil, fmt.Errorf("secp256k1Point.UnmarshalBinary: x coordinate out of range")
	}
	if !secp256k1.DecompressY(&out.value.X, false, &out.value.Y) {
		return nil, fmt.Errorf("secp256k1Point.UnmarshalBinary: x coordinate not on curve")
	}
	return out, nil
}

func (Secp256k1) Name() string {
	return "secp256k1"
}

type Secp256k1Scalar struct {
	value secp256k1.ModNScalar
}

func secp256k1CastScalar(generic Scalar) *Secp256k1Scalar {
	out, ok := generic.(*Secp256k1Scalar)
	if !ok {
		panic(fmt.Sprintf("failed to convert to secp256k1Scalar: %v", generic))
	}
	return out
}

func (*Secp256k1Scalar) Curve() Curve {
	return Secp256k1{}
}

func (s *Secp256k1Scalar) MarshalBinary() ([]byte, error) {
	data := s.value.Bytes()
	return data[:], nil
}

func (s *Secp256k1Scalar) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid length for secp256k1 scalar: %d", len(data))
	}
	var exactData [32]byte
	copy(exactData[:], data)
	if s.value.SetBytes(&exactData) != 0 {
		return errors.New("invalid bytes for secp256k1 scalar")
	}
	return nil
}

func (s *Secp256k1Scalar) Add(that Scalar) Scalar {
	other := secp256k1CastScalar(that)

	s.value.Add(&other.value)
	return s
}

func (s *Secp256k1Scalar) Sub(that Scalar) Scalar {
	other := secp256k1CastScalar(that)

	negated := new(Secp256k1Scalar)
	negated.value.Set(&other.value)
	negated.value.Negate()

	s.value.Add(&negated.value)
	return s
}

func (s *Secp256k1Scalar) Mul(that Scalar) Scalar {
	other := secp256k1CastScalar(that)

	s.value.Mul(&other.value)
	return s
}

func (s *Secp256k1Scalar) Invert() Scalar {
	s.value.InverseNonConst()
	return s
}

func (s *Secp256k1Scalar) Negate() Scalar {
	s.value.Negate()
	return s
}

func (s *Secp256k1Scalar) IsOverHalfOrder() bool {
	return s.value.IsOverHalfOrder()
}

func (s *Secp256k1Scalar) Equal(that Scalar) bool {
	other := secp256k1CastScalar(that)

	return s.value.Equals(&other.value)
}

func (s *Secp256k1Scalar) IsZero() bool {
	return s.value.IsZero()
}

func (s *Secp256k1Scalar) Set(that Scalar) Scalar {
	other := secp256k1CastScalar(that)

	s.value.Set(&other.value)
	return s
}

func (s *Secp256k1Scalar) SetNat(x *saferith.Nat) Scalar {
	reduced := new(saferith.Nat).Mod(x, secp256k1Order)
	s.value.SetByteSlice(reduced.Bytes())
	return s
}

func (s *Secp256k1Scalar) Act(that Point) Point {
	other := secp256k1CastPoint(that)
	out := new(Secp256k1Point)
	secp256k1.ScalarMultNonConst(&s.value, &other.value, &out.value)
	return out
}

func (s *Secp256k1Scalar) ActOnBase() Point {
	out := new(Secp256k1Point)
	secp256k1.ScalarBaseMultNonConst(&s.value, &out.value)
	return out
}

type Secp256k1Point struct {
	value secp256k1.JacobianPoint
}

func secp256k1CastPoint(generic Point) *Secp256k1Point {
	out, ok := generic.(*Secp256k1Point)
	if !ok {
		panic(fmt.Sprintf("failed to convert to secp256k1Point: %v", generic))
	}
	return out
}

func (*Secp256k1Point) Curve() Curve {
	return Secp256k1{}
}

func (p *Secp256k1Point) XBytes() []byte {
	p.value.ToAffine()
	return p.value.X.Bytes()[:]
}

func (p *Secp256k1Point) MarshalBinary() ([]byte, error) {
	out := make([]byte, 33)
	// we clone v to not case a race during a hash.Write
	v := p.value
	v.ToAffine()
	// Doing it this way is compatible with Bitcoin
	out[0] = byte(v.Y.IsOddBit()) + 2
	data := v.X.Bytes()
	copy(out[1:], data[:])
	return out, nil
}

func (p *Secp256k1Point) UnmarshalBinary(data []byte) error {
	if len(data) != 33 {
		return fmt.Errorf("invalid length for secp256k1Point: %d", len(data))
	}
	p.value.Z.SetInt(1)
	if p.value.X.SetByteSlice(data[1:]) {
		return fmt.Errorf("secp256k1Point.UnmarshalBinary: x coordinate out of range")
	}
	if !secp256k1.DecompressY(&p.value.X, data[0] == 3, &p.value.Y) {
		return fmt.Errorf("secp256k1Point.UnmarshalBinary: x coordinate not on curve")
	}
	return nil
}

func (p *Secp256k1Point) Add(that Point) Point {
	other := secp256k1CastPoint(that)

	out := new(Secp256k1Point)
	secp256k1.AddNonConst(&p.value, &other.value, &out.value)
	return out
}

func (p *Secp256k1Point) Sub(that Point) Point {
	return p.Add(that.Negate())
}

func (p *Secp256k1Point) Set(that Point) Point {
	other := secp256k1CastPoint(that)

	p.value.Set(&other.value)
	return p
}

func (p *Secp256k1Point) Negate() Point {
	out := new(Secp256k1Point)
	out.value.Set(&p.value)
	out.value.Y.Negate(1)
	out.value.Y.Normalize()
	return out
}

func (p *Secp256k1Point) Equal(that Point) bool {
	other := secp256k1CastPoint(that)

	p.value.ToAffine()
	other.value.ToAffine()
	return p.value.X.Equals(&other.value.X) && p.value.Y.Equals(&other.value.Y) && p.value.Z.Equals(&other.value.Z)
}

func (p *Secp256k1Point) IsIdentity() bool {
	return p == nil || (p.value.X.IsZero() && p.value.Y.IsZero()) || p.value.Z.IsZero()
}

func (p *Secp256k1Point) HasEvenY() bool {
	p.value.ToAffine()
	return !p.value.Y.IsOdd()
}

func (p *Secp256k1Point) XScalar() Scalar {
	out := new(Secp256k1Scalar)
	p.value.ToAffine()
	out.value.SetBytes(p.value.X.Bytes())
	return out
}
