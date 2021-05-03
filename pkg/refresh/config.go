package refresh

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

type Parameters struct {
	// Map of public keys of all parties
	// { Xⱼ }ⱼ, s.t. ∑ⱼ Xⱼ = X, where X is the ECDSA public key
	PublicSharesECDSA map[uint32]*curve.Point

	// This party's share of the ECDSA key
	// xᵢ s.t. Xᵢ = [xᵢ] G
	PrivateShareECDSA *curve.Scalar

	// ElGamal secret
	y *curve.Scalar

	// Paillier secrets
	p, q, phi      *big.Int
	paillierSecret *paillier.SecretKey

	// Pedersen parameters N, s, t, and λ secret
	ped    *pedersen.Parameters
	lambda *big.Int

	// xSent are the shares we send to other parties
	xSent []*curve.Scalar

	// Schnorr commitment secrets
	aSchnorr []*curve.Scalar // aᵢⱼ <- 𝔽ₚ
	bSchnorr *curve.Scalar   // bᵢ <- 𝔽ₚ

	// This party's random string
	// ρ <- {0,1}³²
	rho []byte
}

func (p *Parameters) fill(c *session.BaseConfig) {
	if p.y == nil {
		p.y = curve.NewScalarRandom()
	}

	var n *big.Int
	if p.p == nil && p.q == nil {
		p.p, p.q, n, p.phi = sample.Paillier()
		paillierPublic := paillier.NewPublicKey(n)
		p.paillierSecret = paillier.NewSecretKey(p.phi, paillierPublic)
	} else {
		n = new(big.Int).Mul(p.p, p.q)
	}

	if p.ped == nil && p.lambda == nil {
		var s, t *big.Int
		s, t, p.lambda = sample.Pedersen(n, p.phi)
		p.ped = &pedersen.Parameters{
			N: n,
			S: s,
			T: t,
		}
	}

	if p.xSent == nil {
		p.xSent = randomZeroSum(c.N())
	}

	if p.bSchnorr == nil {
		p.bSchnorr = curve.NewScalarRandom()
	}

	if p.aSchnorr == nil {
		p.aSchnorr = make([]*curve.Scalar, c.N())
		for j := range c.Parties() {
			p.aSchnorr[j] = curve.NewScalarRandom()
		}
	}

	if p.rho == nil {
		p.rho = make([]byte, params.SecBytes)
		_, _ = rand.Read(p.rho)
	}
}

// verify checks all parameters including all the randomness used
func (p *Parameters) verify(c *session.BaseConfig) bool {
	if p.y == nil ||
		p.p == nil || p.q == nil || p.phi == nil || p.paillierSecret == nil ||
		p.ped == nil || p.lambda == nil ||
		p.ped.S == nil || p.ped.T == nil || p.ped.N == nil ||
		p.bSchnorr == nil {
		return false
	}

	if len(p.xSent) != c.N() || len(p.aSchnorr) != c.N() || len(p.rho) != params.SecBytes {
		return false
	}

	if p.bSchnorr.IsZero() || p.y.IsZero() || p.lambda.Sign() == 0 {
		return false
	}

	if p.ped.N.Cmp(p.paillierSecret.PublicKey().N()) != 0 {
		return false
	}

	if bytes.Equal(p.rho, make([]byte, params.SecBytes)) {
		return false
	}

	if !p.ped.IsValid() {
		return false
	}

	for _, a := range p.aSchnorr {
		if a.IsZero() {
			return false
		}
	}

	return true
}

func randomZeroSum(n int) []*curve.Scalar {
	x := make([]*curve.Scalar, n)
	sum := curve.NewScalar()
	for j := 0; j < n-1; j++ {
		x[j] = curve.NewScalarRandom()
		sum.Add(sum, x[j])
	}
	sum.Negate(sum)
	x[n-1] = sum
	return x
}

// Verify makes sure that the parameters are compatible with the configuration
func (p *Parameters) Verify(c *session.BaseConfig) error {
	// is our own key the identity
	if p.PrivateShareECDSA == nil || p.PrivateShareECDSA.Equal(curve.NewScalar()) == 1 {
		return errors.New("PrivateShareECDSA is nil or equal to 0")
	}

	// correct number of keys
	if len(p.PublicSharesECDSA) != c.N() {
		return errors.New("wrong number of public shares")
	}

	for _, j := range c.Parties() {
		// is the party included
		x, ok := p.PublicSharesECDSA[j]
		if !ok {
			return fmt.Errorf("PublicSharesECDSA for party %d is not present", j)
		}

		// are any points the identity
		if x.IsIdentity() {
			return fmt.Errorf("PublicSharesECDSA for party %d is identity", j)
		}

		// is our own key correct
		if j == c.SelfID() {
			xComp := curve.NewIdentityPoint().ScalarBaseMult(p.PrivateShareECDSA)
			if xComp.Equal(x) != 1 {
				return errors.New("PublicSharesECDSA for self party does not correspond with PrivateShareECDSA")
			}
		}
	}
	return nil
}
