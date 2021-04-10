package pedersen

import (
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
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

func Generate(N, phi *big.Int) (s, t, lambda *big.Int) {
	s, t = new(big.Int), new(big.Int)
	lambda = sample.Unit(N)

	// sample d without statistical bias
	d := sample.PlusMinus(params.L, true)
	d.Mod(d, phi)

	tau := sample.Unit(N)

	t.Exp(tau, two, N)
	s.Exp(t, d, N)

	return
}

func NewPedersen(N, phi *big.Int) (*Verifier, *big.Int) {
	var s, t big.Int
	tau := sample.Unit(N)
	d, err := rand.Int(rand.Reader, phi)
	if err != nil {
		panic("failed to sample Pedersen lambda")
	}
	t.Exp(tau, two, N)
	s.Exp(&t, d, N)

	p := &Verifier{
		N: N,
		S: &s,
		T: &t,
	}
	return p, d
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
