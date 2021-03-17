package pedersen

import (
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/sample"
)

var two = big.NewInt(2)

type Verifier struct {
	N, S, T *big.Int
}

// Commit sets the variable result to
//   s^secret t^blind
func (v *Verifier) Commit(secret, blind *big.Int) *big.Int {
	var result, tmp big.Int

	result.Exp(v.S, secret, v.N)
	tmp.Exp(v.T, blind, v.N)
	result.Mul(&result, &tmp)
	result.Mod(&result, v.N)
	return &result
}

func NewPedersen(N, phi *big.Int) *Verifier {
	var s, t big.Int
	r := sample.Unit(N)
	lambda, err := rand.Int(rand.Reader, phi)
	if err != nil {
		panic("failed to sample Pedersen lambda")
	}
	t.Exp(r, two, N)
	s.Exp(&t, lambda, N)

	p := &Verifier{
		N: N,
		S: &s,
		T: &t,
	}
	return p
}

func (v *Verifier) Verify(sPow, tPow, S, T, e *big.Int) bool {
	var lhs, rhs big.Int
	lhs.Exp(v.S, sPow, v.N)
	rhs.Exp(v.T, tPow, v.N)
	lhs.Mul(&lhs, &rhs)
	lhs.Mod(&lhs, v.N)

	rhs.Exp(T, e, v.N)
	rhs.Mul(&rhs, S)
	rhs.Mod(&rhs, v.N)

	return lhs.Cmp(&rhs) == 0
}
