package refresh

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

	// xSent are the shares we send to other LocalParties
	// ∑ᵢ xSent[i] = 0
	xSent []*curve.Scalar

	// Schnorr commitment secrets
	aSchnorr []*curve.Scalar // aᵢⱼ <- 𝔽ₚ

	// This party's random string
	// ρ <- {0,1}³²
	rho []byte
}
