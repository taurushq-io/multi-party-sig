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
	SetUInt32(uint322 uint32) Scalar
	Act(Point) Point
	ActOnBase() Point
}

type Point interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Curve() Curve
	Add(Point) Point
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

type MarshallableScalar struct {
	Scalar
	group Curve
}

func NewMarshallableScalar(s Scalar) *MarshallableScalar {
	return &MarshallableScalar{Scalar: s, group: s.Curve()}
}

func (m *MarshallableScalar) MarshalBinary() ([]byte, error) {
	name := []byte(m.group.Name())
	data, err := m.Scalar.MarshalBinary()
	if err != nil {
		return nil, err
	}
	nameLen := uint32(len(name))
	out := make([]byte, 4+len(name)+len(data))
	binary.BigEndian.PutUint32(out, nameLen)
	copy(out[4:], name)
	copy(out[4+len(name):], data)
	return out, nil
}

func (m *MarshallableScalar) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("MarshallableScalar.UnmarshalBinary: data too short")
	}
	nameLen := int(binary.BigEndian.Uint32(data))
	if nameLen > len(data)+4 {
		return errors.New("MarshallableScalar.UnmarshalBinary: data too short")
	}
	name := string(data[4 : 4+nameLen])
	group, err := curveFromName(name)
	if err != nil {
		return err
	}
	m.group = group
	m.Scalar = group.NewScalar()
	if err := m.Scalar.UnmarshalBinary(data[4+nameLen:]); err != nil {
		return err
	}
	return nil
}
