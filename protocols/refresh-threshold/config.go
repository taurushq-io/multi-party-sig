package refresh_threshold

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

type Parameters struct {
	// fᵢ(X) of degree t
	poly *polynomial.Polynomial

	// Paillier secrets
	p, q, phi      *big.Int
	paillierSecret *paillier.SecretKey

	// Pedersen parameters N, s, t, and λ secret
	ped    *pedersen.Parameters
	lambda *big.Int

	// xSent are the shares we send to other parties
	// ∑ᵢ xSent[i] = 0
	xSent []*curve.Scalar

	// Schnorr commitment secrets
	aSchnorr []*curve.Scalar // aᵢⱼ <- 𝔽ₚ

	// This party's random string
	// ρ <- {0,1}³²
	rho []byte
}

//func (p *Parameters) fill(parties party.IDSlice) {
//	N := len(parties)
//	if p.y == nil {
//		p.y = curve.NewScalarRandom()
//	}
//
//	var n *big.Int
//	if p.p == nil && p.q == nil {
//		p.p, p.q, n, p.phi = sample.Paillier()
//		paillierPublic := paillier.NewPublicKey(n)
//		p.paillierSecret = paillier.NewSecretKeyFromPrimes(p.phi, paillierPublic)
//	} else {
//		n = new(big.Int).Mul(p.p, p.q)
//	}
//
//	if p.ped == nil && p.lambda == nil {
//		var s, t *big.Int
//		s, t, p.lambda = sample.Pedersen(n, p.phi)
//		p.ped = &pedersen.Parameters{
//			N: n,
//			S: s,
//			T: t,
//		}
//	}
//
//	if p.xSent == nil {
//		p.xSent = randomZeroSum(N)
//	}
//
//	if p.bSchnorr == nil {
//		p.bSchnorr = curve.NewScalarRandom()
//	}
//
//	if p.aSchnorr == nil {
//		p.aSchnorr = make([]*curve.Scalar, N)
//		for j := range parties {
//			p.aSchnorr[j] = curve.NewScalarRandom()
//		}
//	}
//
//	if p.rho == nil {
//		p.rho = make([]byte, params.SecBytes)
//		_, _ = rand.Read(p.rho)
//	}
//}
//
//// verify checks all parameters including all the randomness used
//func (p *Parameters) verify(n int) bool {
//	if p.y == nil ∥
//		p.p == nil ∥ p.q == nil ∥ p.phi == nil ∥ p.paillierSecret == nil ∥
//		p.ped == nil ∥ p.lambda == nil ∥
//		p.ped.S == nil ∥ p.ped.T == nil ∥ p.ped.N == nil ∥
//		p.bSchnorr == nil {
//		return false
//	}
//
//	if len(p.xSent) != n ∥ len(p.aSchnorr) != n ∥ len(p.rho) != params.SecBytes {
//		return false
//	}
//
//	if p.bSchnorr.IsZero() ∥ p.y.IsZero() ∥ p.lambda.Sign() == 0 {
//		return false
//	}
//
//	if p.ped.N.Cmp(p.paillierSecret.PublicKey().N) != 0 {
//		return false
//	}
//
//	if bytes.Equal(p.rho, make([]byte, params.SecBytes)) {
//		return false
//	}
//
//	if !p.ped.Validate() {
//		return false
//	}
//
//	for _, a := range p.aSchnorr {
//		if a.IsZero() {
//			return false
//		}
//	}
//
//	return true
//}
//
//func randomZeroSum(n int) []*curve.Scalar {
//	x := make([]*curve.Scalar, n)
//	sum := curve.NewScalar()
//	for j := 0; j < n-1; j++ {
//		x[j] = curve.NewScalarRandom()
//		sum.Add(sum, x[j])
//	}
//	sum.Negate(sum)
//	x[n-1] = sum
//	return x
//}
