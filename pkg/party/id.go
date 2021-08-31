package party

import (
	"errors"
	"io"

	"github.com/cronokirby/safenum"
	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

// ID represents a unique identifier for a participant in our scheme.
//
// You should think of this as a 32 byte slice. We represent it as a string
// to have a comparable type, but using more than 32 bytes will lead to inconsistencies
// because of how we use this ID numerically later.
//
// This ID is used as an interpolation point of a polynomial sharing of the secret key.
type ID string

// Scalar converts this ID into a scalar.
//
// All of the IDs of our participants form a polynomial sharing of the secret
// scalar value used for ECDSA.
func (id ID) Scalar(group curve.Curve) curve.Scalar {
	return group.NewScalar().SetNat(new(safenum.Nat).SetBytes([]byte(id)))
}

// WriteTo makes ID implement the io.WriterTo interface.
//
// This writes out the content of this ID, in a domain separated way.
func (id ID) WriteTo(w io.Writer) (int64, error) {
	if id == "" {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := w.Write([]byte(id))
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (ID) Domain() string {
	return "ID"
}

// PointMap is a map from party ID's to points, to be easy to marshal.
//
// When unmarshalling, EmptyPointMap must be called first, to provide a group
// to use to unmarshal the points.
type PointMap struct {
	group  curve.Curve
	Points map[ID]curve.Point
}

// NewPointMap creates a PointMap from a map of points.
func NewPointMap(points map[ID]curve.Point) *PointMap {
	var group curve.Curve
	for _, v := range points {
		group = v.Curve()
		break
	}
	return &PointMap{group: group, Points: points}
}

// EmptyPointMap creates an empty PointMap with a fixed group, ready to be unmarshalled.
//
// This needs to be used before unmarshalling, so that we have a group to unmarshal
// the points inside of the map.
func EmptyPointMap(group curve.Curve) *PointMap {
	return &PointMap{group: group}
}

func (m *PointMap) MarshalBinary() ([]byte, error) {
	pointBytes := make(map[ID]cbor.RawMessage, len(m.Points))
	var err error
	for k, v := range m.Points {
		pointBytes[k], err = cbor.Marshal(v)
		if err != nil {
			return nil, err
		}
	}
	return cbor.Marshal(pointBytes)
}

func (m *PointMap) UnmarshalBinary(data []byte) error {
	if m.group == nil {
		return errors.New("PointMap.UnmarshalBinary called without setting a group")
	}
	pointBytes := make(map[ID]cbor.RawMessage)
	if err := cbor.Unmarshal(data, &pointBytes); err != nil {
		return err
	}
	m.Points = make(map[ID]curve.Point, len(pointBytes))
	for k, v := range pointBytes {
		point := m.group.NewPoint()
		if err := cbor.Unmarshal(v, point); err != nil {
			return err
		}
		m.Points[k] = point
	}
	return nil
}
