package curve

import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cronokirby/safenum"
)

type Curve interface {
	NewPoint() Point
	NewBasePoint() Point
	NewScalar() Scalar
	Name() string
	SafeScalarBytes() int
	Order() *safenum.Modulus
}

type Scalar interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Curve() Curve
	Add(Scalar) Scalar
	Sub(Scalar) Scalar
	Negate() Scalar
	Mul(Scalar) Scalar
	Invert() Scalar
	Equal(Scalar) bool
	IsZero() bool
	Set(Scalar) Scalar
	SetNat(*safenum.Nat) Scalar
	Act(Point) Point
	ActOnBase() Point
}

type Point interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Curve() Curve
	Add(Point) Point
	Sub(Point) Point
	Negate() Point
	Set(Point) Point
	Equal(Point) bool
	IsIdentity() bool
}

func curveFromName(name string) (Curve, error) {
	switch name {
	case "secp256k1":
		return Secp256k1{}, nil
	default:
		return nil, fmt.Errorf("unknown curve: %s", name)
	}
}

func marshalPrefixed(name string, m encoding.BinaryMarshaler) ([]byte, error) {
	nameBytes := []byte(name)
	data, err := m.MarshalBinary()
	if err != nil {
		return nil, err
	}
	nameLen := uint32(len(nameBytes))
	out := make([]byte, 4+len(nameBytes)+len(data))
	binary.BigEndian.PutUint32(out, nameLen)
	copy(out[4:], nameBytes)
	copy(out[4+len(nameBytes):], data)

	return out, nil
}

func unmarshalPrefixed(data []byte) (Curve, []byte, error) {
	if len(data) < 4 {
		return nil, nil, errors.New("unmarshalPrefixed: data too short")
	}
	nameLen := int(binary.BigEndian.Uint32(data))
	if nameLen > len(data)+4 {
		return nil, nil, errors.New("unmarshalPrefixed: data too short")
	}
	name := string(data[4 : 4+nameLen])
	group, err := curveFromName(name)
	if err != nil {
		return nil, nil, err
	}
	return group, data[4+nameLen:], nil
}

type MarshallableScalar struct {
	Scalar Scalar
	group  Curve
}

func NewMarshallableScalar(s Scalar) *MarshallableScalar {
	return &MarshallableScalar{Scalar: s, group: s.Curve()}
}

func (m *MarshallableScalar) MarshalBinary() ([]byte, error) {
	return marshalPrefixed(m.group.Name(), m.Scalar)
}

func (m *MarshallableScalar) UnmarshalBinary(data []byte) error {
	group, scalarData, err := unmarshalPrefixed(data)
	if err != nil {
		return err
	}
	m.group = group
	m.Scalar = group.NewScalar()
	if err := m.Scalar.UnmarshalBinary(scalarData); err != nil {
		return err
	}
	return nil
}

type MarshallablePoint struct {
	Point Point
	group Curve
}

func NewMarshallablePoint(p Point) *MarshallablePoint {
	return &MarshallablePoint{Point: p, group: p.Curve()}
}

func (m *MarshallablePoint) MarshalBinary() ([]byte, error) {
	return marshalPrefixed(m.group.Name(), m.Point)
}

func (m *MarshallablePoint) UnmarshalBinary(data []byte) error {
	group, scalarData, err := unmarshalPrefixed(data)
	if err != nil {
		return err
	}
	m.group = group
	m.Point = group.NewPoint()
	if err := m.Point.UnmarshalBinary(scalarData); err != nil {
		return err
	}
	return nil
}

func MakeInt(s Scalar) *safenum.Int {
	bytes, err := s.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return new(safenum.Int).SetBytes(bytes)
}
