package sign

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

type Signature struct {
	R *curve.Point
	S *curve.Scalar
}

// Verify is a custom signature format using curve data.
func (sig Signature) Verify(X *curve.Point, hash []byte) bool {
	m := curve.NewScalar().SetHash(hash)
	sInv := curve.NewScalar().Invert(sig.S)
	mG := curve.NewIdentityPoint().ScalarBaseMult(m)
	r := sig.R.XScalar()
	rX := curve.NewIdentityPoint().ScalarMult(r, X)
	R2 := curve.NewIdentityPoint().Add(mG, rX)
	R2.ScalarMult(sInv, R2)
	return R2.Equal(sig.R)
}

// ToRS returns R, S such that ecdsa.Verify(pub,message, R, S) == true.
func (sig Signature) ToRS() (*big.Int, *big.Int) {
	return sig.R.XScalar().BigInt(), sig.S.BigInt()
}
