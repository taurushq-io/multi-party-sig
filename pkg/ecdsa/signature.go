package ecdsa

import (
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

type Signature struct {
	R curve.Point
	S curve.Scalar
}

// EmptySignature returns a new signature with a given curve, ready to be unmarshalled.
func EmptySignature(group curve.Curve) Signature {
	return Signature{R: group.NewPoint(), S: group.NewScalar()}
}

// Verify is a custom signature format using curve data.
func (sig Signature) Verify(X curve.Point, hash []byte) bool {
	group := X.Curve()

	m := curve.FromHash(group, hash)
	sInv := group.NewScalar().Set(sig.S).Invert()
	mG := m.ActOnBase()
	r := sig.R.XScalar()
	rX := r.Act(X)
	R2 := mG.Add(rX)
	R2 = sInv.Act(R2)
	return R2.Equal(sig.R)
}


// get a signature in ethereum format
func (sig Signature) SigEthereum() ([]byte, error) {
	IsOverHalfOrder := sig.S.IsOverHalfOrder() // s-values greater than secp256k1n/2 are considered invalid

	if IsOverHalfOrder {
		sig.S.Negate()
	}

	r, err := sig.R.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s, err := sig.S.MarshalBinary()
	if err != nil {
		return nil, err
	}

	rs := make([]byte, 0, 65)
	rs = append(rs, r...)
	rs = append(rs, s...)

	if IsOverHalfOrder {
		v := rs[0] - 2 // Convert to Ethereum signature format with 'recovery id' v at the end.
		copy(rs, rs[1:])
		rs[64] = v ^ 1
	} else {
		v := rs[0] - 2
		copy(rs, rs[1:])
		rs[64] = v
	}

	r[0] = rs[64] + 2
	if err := sig.R.UnmarshalBinary(r); err != nil {
		return nil, err
	}

	return rs, nil
}