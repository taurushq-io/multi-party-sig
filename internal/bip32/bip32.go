package bip32

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

func compressPoint(p *curve.Point) []byte {
	out := make([]byte, 33)
	out[0] = 3
	if p.HasEvenY() {
		out[0] = 2
	}
	copy(out[1:], p.XBytes()[:])
	return out
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
func DeriveScalar(public *curve.Point, chaining []byte, i uint32) (*curve.Scalar, []byte, error) {
	if i>>31 != 0 {
		panic("DeriveScalar doesn't work with hardened keys.")
	}

	h := hmac.New(sha512.New, chaining)
	_, _ = h.Write(compressPoint(public))
	iBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(iBytes, i)
	h.Write(iBytes)

	out := h.Sum(nil)
	scalar, ok := curve.NewScalar().SetBytes(out[:32])
	if !ok {
		return nil, nil, fmt.Errorf("bad index: %d", i)
	}

	return scalar, out[32:], nil
}
