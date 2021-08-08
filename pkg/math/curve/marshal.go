package curve

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/taurusgroup/multi-party-sig/internal/params"
)

// MarshalBinary implements encoding.BinaryMarshaler.
func (s *Scalar) MarshalBinary() ([]byte, error) {
	data := make([]byte, params.BytesScalar)
	s.s.PutBytesUnchecked(data)
	return data, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	var scalar secp256k1.ModNScalar
	if len(data) < params.BytesScalar {
		return errors.New("curve.Scalar.Unmarshal: data is too small")
	}
	if scalar.SetByteSlice(data[:params.BytesScalar]) {
		return errors.New("curve.Scalar.Unmarshal: scalar was >= q")
	}
	s.s.Set(&scalar)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (s Scalar) MarshalJSON() ([]byte, error) {
	data, _ := s.MarshalBinary()
	return json.Marshal(data)
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *Scalar) UnmarshalJSON(bytes []byte) error {
	var data []byte
	if err := json.Unmarshal(bytes, &data); err != nil {
		return fmt.Errorf("curve.Point: failed to unmarshal compressed point: %w", err)
	}
	return s.UnmarshalBinary(data)
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (v *Point) MarshalBinary() (data []byte, err error) {
	if v == nil {
		return nil, errors.New("curve.Point.MarshalToSizedBuffer: point is nil")
	}
	v.toAffine()
	if v.IsIdentity() {
		return nil, errors.New("curve.Point.MarshalToSizedBuffer: tries to marshal identity")
	}

	data = make([]byte, params.BytesPoint)
	// Choose the format byte depending on the oddness of the Y coordinate.
	format := secp256k1.PubKeyFormatCompressedEven
	if v.p.Y.IsOdd() {
		format = secp256k1.PubKeyFormatCompressedOdd
	}

	// 0x02 or 0x03 ∥ 32-byte x coordinate
	data[0] = format
	v.p.X.PutBytesUnchecked(data[1:33])
	return data, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (v *Point) UnmarshalBinary(data []byte) error {
	if len(data) < params.BytesPoint {
		return errors.New("curve.Point.Unmarshal: data is too small")
	}
	format := data[0]
	if !(format == secp256k1.PubKeyFormatCompressedOdd || format == secp256k1.PubKeyFormatCompressedEven) {
		return errors.New("curve.Point.Unmarshal: incorrect format")
	}

	var x, y secp256k1.FieldVal
	// Parse the x and y coordinates while ensuring that they are in the
	// allowed range.
	if overflow := x.SetByteSlice(data[1:33]); overflow {
		return errors.New("curve.Point.Unmarshal: invalid point: x >= field prime")
	}

	// Attempt to calculate the y coordinate for the given x coordinate such
	// that the result pair is a point on the secp256k1 curve and the
	// solution with desired oddness is chosen.
	wantOddY := format == secp256k1.PubKeyFormatCompressedOdd
	if !secp256k1.DecompressY(&x, wantOddY, &y) {
		return fmt.Errorf("curve.Point.Unmarshal: invalid point: x coordinate %v is not on the secp256k1 curve", x)
	}
	y.Normalize()
	v.p.X.Set(&x)
	v.p.Y.Set(&y)
	v.p.Z.SetInt(1)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (v *Point) MarshalJSON() ([]byte, error) {
	data, err := v.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

// UnmarshalJSON implements json.Unmarshaler.
func (v *Point) UnmarshalJSON(bytes []byte) error {
	var data []byte
	if err := json.Unmarshal(bytes, &data); err != nil {
		return fmt.Errorf("curve.Point: failed to unmarshal compressed point: %w", err)
	}
	return v.UnmarshalBinary(data)
}

// String implements fmt.Stringer.
func (v *Point) String() string {
	if v == nil {
		return "nil"
	}
	if v.IsIdentity() {
		return "Point{Identity}"
	}
	s := fmt.Sprintf("Point{X: %v, Y: %v, Z: %v", v.p.X, v.p.Y, v.p.Z)
	return s
}

// String implements fmt.Stringer.
func (s *Scalar) String() string {
	if s == nil {
		return "nil"
	}
	return s.s.String()
}
