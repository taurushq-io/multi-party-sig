package curve

import (
	"encoding/json"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

func (v Point) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.Bytes())
}

func (v *Point) UnmarshalJSON(bytes []byte) error {
	var data []byte
	if err := json.Unmarshal(bytes, &data); err != nil {
		return fmt.Errorf("curve.Point: failed to unmarshal compressed point: %w", err)
	}
	if _, err := v.SetBytes(data); err != nil {
		return fmt.Errorf("curve.Point: failed to unmarshal compressed point: %w", err)
	}
	return nil
}

func (s Scalar) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.s.Bytes())
}

func (s *Scalar) UnmarshalJSON(bytes []byte) error {
	data := make([]byte, params.BytesScalar)
	if err := json.Unmarshal(bytes, &data); err != nil {
		return fmt.Errorf("curve.Point: failed to unmarshal compressed point: %w", err)
	}
	s.s.SetBytes(data)
	return nil
}
