package bip32

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

// DeriveMaster uses a secret seed to derive a scalar and chaining value.
//
// This scalar serves as the master secret key. Together with the chaining
// value, it forms the extended master secret key.
//
// If an error is returned, this means that this seed is not useable, and a new
// seed should be generated instead.
func DeriveMaster(seed []byte) (*curve.Secp256k1Scalar, []byte, error) {
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))

	_, _ = h.Write(seed)

	out := h.Sum(nil)
	scalar := new(curve.Secp256k1Scalar)
	err := scalar.UnmarshalBinary(out[:32])
	if err != nil || scalar.IsZero() {
		return nil, nil, fmt.Errorf("bad seed: %s", seed)
	}

	return scalar, out[32:], nil
}

// DeriveScalar uses a public point, chaining value, and index, to derive a scalar and chaining value.
//
// This scalar should be added to the secret key.
//
// If an error is returned, this means that this index will not be useable, and another
// index should be used instead.
//
// This function will panic if an index for a hardened key is used.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func DeriveScalar(public *curve.Secp256k1Point, chaining []byte, i uint32) (*curve.Secp256k1Scalar, []byte, error) {
	if i>>31 != 0 {
		panic("DeriveScalar doesn't work with hardened keys.")
	}

	h := hmac.New(sha512.New, chaining)
	compressed, _ := public.MarshalBinary()
	_, _ = h.Write(compressed)
	iBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(iBytes, i)
	h.Write(iBytes)

	out := h.Sum(nil)
	scalar := new(curve.Secp256k1Scalar)
	err := scalar.UnmarshalBinary(out[:32])
	if err != nil || scalar.IsZero() {
		return nil, nil, fmt.Errorf("bad index: %d", i)
	}

	return scalar, out[32:], nil
}

// DeriveScalarForPath uses a public point, chaining value, and path to derive
// a scalar and chaining value.
//
// This scalar should be added to the secret key underlying the public point.
//
// If an error is returned, this means that an index in this path will not be
// useable, and another path should be used instead.
//
// This function will panic if an index for a hardened key is used.
func DeriveScalarForPath(public *curve.Secp256k1Point, chaining []byte, path Path) (*curve.Secp256k1Scalar, []byte, error) {
	totalTweak := curve.Secp256k1{}.NewScalar()

	for _, index := range path.indices {
		totalTweakG := totalTweak.ActOnBase()
		parentPublic := public.Add(totalTweakG).(*curve.Secp256k1Point)

		var tweak *curve.Secp256k1Scalar
		var err error
		tweak, chaining, err = DeriveScalar(parentPublic, chaining, index)

		if err != nil {
			return nil, nil, err
		}

		totalTweak.Add(tweak)
	}

	return totalTweak.(*curve.Secp256k1Scalar), chaining, nil
}
