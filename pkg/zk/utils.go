package zk

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
)

// Affine returns a pb.Int: a + bc
func Affine(a, b, c *big.Int) *pb.Int {
	var result big.Int
	result.Mul(b, c)
	result.Add(&result, a)
	return pb.NewInt(&result)
}

// AffineNonce r ρᵉ mod pk
func AffineNonce(r, rho, e *big.Int, pk *paillier.PublicKey) *pb.Int {
	var result big.Int
	result.Exp(rho, e, pk.N)
	result.Mul(&result, r)
	result.Mod(&result, pk.N)
	return pb.NewInt(&result)
}
