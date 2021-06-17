package party

import "github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"

type ID string

func (id ID) Scalar() *curve.Scalar {
	var s curve.Scalar
	buffer := make([]byte, 32)
	copy(buffer, id)
	s.SetBytes(buffer)
	return &s
}
