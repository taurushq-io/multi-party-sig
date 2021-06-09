package pb

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

// PointCaster handles point operations
type PointCaster struct{}

// Equal returns true if the provided points are equal
func (c *PointCaster) Equal(a, b *curve.Point) bool {
	if a == nil {
		return b == nil
	}
	return a.Equal(b)
}

// Size returns the size of a point
func (c *PointCaster) Size(a *curve.Point) int {
	if a == nil || a.IsIdentity() {
		return 1
	}
	return 1 + params.BytesPoint
}

// MarshalTo marshals the first parameter to the second one
func (c *PointCaster) MarshalTo(a *curve.Point, buf []byte) (int, error) {
	if a == nil || a.IsIdentity() {
		buf[0] = 0
		return 1, nil
	}
	bytes := a.Bytes()
	if len(buf) < len(bytes) {
		//todo fix err
		return 0, errors.New("invalid")
	}
	copy(buf, bytes)
	return params.BytesPoint, nil
}

// Unmarshal unmarshalls the parameter to a point
func (c *PointCaster) Unmarshal(buf []byte) (*curve.Point, error) {
	switch len(buf) {
	case 0:
		return nil, fmt.Errorf("bad input")
	case 1:
		return curve.NewIdentityPoint(), nil
	}
	return curve.NewIdentityPoint().SetBytes(buf[:params.BytesPoint])
}

// NewPopulated returns a new instance of a point, pre-populated with a zero
func (c *PointCaster) NewPopulated() *curve.Point {
	return curve.NewIdentityPoint()
}
