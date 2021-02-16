package arith

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"math/big"
)

func GetBigInt(s kyber.Scalar) *big.Int {
	if i, ok := s.(*mod.Int); ok {
		return &i.V
	}
	panic("wrong scalar")
	return nil
}
