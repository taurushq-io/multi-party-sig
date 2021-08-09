package curve

import (
	"errors"
	"fmt"

	"github.com/cronokirby/safenum"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

type Secp256k1 struct{}

func (Secp256k1) NewPoint() PointI {
	return new(secp256k1Point)
}

func (Secp256k1) NewScalar() ScalarI {
	return new(secp256k1Scalar)
}

type secp256k1Scalar struct {
	value secp256k1.ModNScalar
}

func secp256k1CastScalar(generic ScalarI) *secp256k1Scalar {
	out, ok := generic.(*secp256k1Scalar)
	if !ok {
		panic(fmt.Sprintf("failed to convert to secp256k1Scalar: %v", generic))
	}
	return out
}

func (s *secp256k1Scalar) MarshalBinary() ([]byte, error) {
	data := s.value.Bytes()
	return data[:], nil
}

func (s *secp256k1Scalar) UnmarshalBinary(data []byte) error {
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

func (s *secp256k1Scalar) Add(that ScalarI) ScalarI {
	other := secp256k1CastScalar(that)

	s.value.Add(&other.value)
	return s
}

func (s *secp256k1Scalar) Mul(that ScalarI) ScalarI {
	other := secp256k1CastScalar(that)

	s.value.Mul(&other.value)
	return s
}

func (s *secp256k1Scalar) Invert() ScalarI {
	s.value.InverseNonConst()
	return s
}

func (s *secp256k1Scalar) Negate() ScalarI {
	s.value.Negate()
	return s
}

func (s *secp256k1Scalar) Equal(that ScalarI) bool {
	other := secp256k1CastScalar(that)

	return s.value.Equals(&other.value)
}

func (s *secp256k1Scalar) IsZero() bool {
	return s.value.IsZero()
}

func (s *secp256k1Scalar) Set(that ScalarI) ScalarI {
	return s
}

func (s *secp256k1Scalar) SetNat(x *safenum.Nat) ScalarI {
	return s
}

func (s *secp256k1Scalar) Act(that PointI) PointI {
	other := secp256k1CastPoint(that)
	out := new(secp256k1Point)
	secp256k1.ScalarMultNonConst(&s.value, &other.value, &out.value)
	return out
}

func (s *secp256k1Scalar) ActOnBase() PointI {
	out := new(secp256k1Point)
	secp256k1.ScalarBaseMultNonConst(&s.value, &out.value)
	return out
}

type secp256k1Point struct {
	value secp256k1.JacobianPoint
}

func secp256k1CastPoint(generic PointI) *secp256k1Point {
	out, ok := generic.(*secp256k1Point)
	if !ok {
		panic(fmt.Sprintf("failed to convert to secp256k1Point: %v", generic))
	}
	return out
}

func (p *secp256k1Point) MarshalBinary() ([]byte, error) {
	out := make([]byte, 33)
	// This will modify p, but still return an equivalent value
	p.value.ToAffine()
	// Doing it this way is compatible with Bitcoin
	out[0] = byte(p.value.Y.IsOddBit()) + 2
	data := p.value.X.Bytes()
	copy(out[1:], data[:])
	return out, nil
}

func (p *secp256k1Point) UnmarshalBinary(data []byte) error {
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

func (p *secp256k1Point) Add(that PointI) PointI {
	other := secp256k1CastPoint(that)

	out := new(secp256k1Point)
	secp256k1.AddNonConst(&p.value, &other.value, &out.value)
	return out
}

func (p *secp256k1Point) Negate() PointI {
	out := new(secp256k1Point)
	out.value.Set(&p.value)
	out.value.Y.Negate(1)
	out.value.Y.Normalize()
	return nil
}

func (p *secp256k1Point) Equal(that PointI) bool {
	other := secp256k1CastPoint(that)

	p.value.ToAffine()
	other.value.ToAffine()
	return p.value.X.Equals(&other.value.X) && p.value.Y.Equals(&other.value.Y) && p.value.Z.Equals(&other.value.Z)
}
