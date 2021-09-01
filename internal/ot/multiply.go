package ot

import (
	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

// encode converts a scalar to a sequence of bits, using a certain number of scalars for noise.
//
// The noise should be public, but the encoding will be unpredictable, but still decodable.
func encode(beta curve.Scalar, noise []curve.Scalar) ([]byte, error) {
	// This follows Algorithm 4 in Doerner's paper:
	//   https://eprint.iacr.org/2018/499
	group := beta.Curve()

	gamma := make([]byte, (len(noise)+7)/8)

	acc := group.NewScalar().Set(beta)
	mulNat := new(safenum.Nat)
	mul := group.NewScalar()
	for i := 0; i < len(noise); i++ {
		mulNat.SetUint64(uint64((gamma[i>>3] >> (i & 0b111)) & 1))
		acc.Sub(mul.SetNat(mulNat).Mul(noise[i]))
	}

	data, err := acc.MarshalBinary()
	if err != nil {
		return nil, err
	}

	data = append(data, gamma...)
	return data, nil
}
