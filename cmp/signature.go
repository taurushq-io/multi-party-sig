package cmp

import (
	"crypto/elliptic"
	"crypto/sha256"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"math/big"
)

type Signature struct {
	R    kyber.Point
	M, S kyber.Scalar
}

func (s *Signature) Verify(pk kyber.Point) bool {
	sInv := suite.Scalar().Inv(s.S)
	r := GetXCoord(s.R)

	R1 := suite.Point().Mul(suite.Scalar().Mul(sInv, s.M), nil)
	R2 := suite.Point().Mul(suite.Scalar().Mul(r, sInv), pk)
	R := suite.Point().Add(R1, R2)
	return R.Equal(s.R)
}

// HashMessageToScalar converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
func HashMessageToScalar(message []byte) kyber.Scalar {
	h := sha256.New()
	h.Write(message)
	hash := h.Sum(nil)

	c := elliptic.P256()
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return mod.NewInt(ret, c.Params().N)
}
