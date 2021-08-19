package ecdsa

import (
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type PreSignature struct {
	Group curve.Curve
	// R = δ⁻¹⋅Γ = δ⁻¹⋅(∑ⱼ Γⱼ) = (∑ⱼδ⁻¹γⱼ)⋅G = k⁻¹⋅G
	R curve.Point
	// RBar[j] = δ⁻¹⋅Δⱼ = (δ⁻¹kⱼ)⋅Γ = (k⁻¹kⱼ)⋅G
	RBar map[party.ID]curve.Point
	// S[j] = χⱼ⋅R
	S map[party.ID]curve.Point
	// KShare = kᵢ
	KShare curve.Scalar
	// ChiShare = χᵢ
	ChiShare curve.Scalar
}

// SignatureShare represents an individual additive share of the signature's "s" component.
type SignatureShare = curve.Scalar

// SignatureShare returns this party's share σᵢ = kᵢm+rχᵢ, where s = ∑ⱼσⱼ
func (sig *PreSignature) SignatureShare(hash []byte) curve.Scalar {
	m := curve.FromHash(sig.Group, hash)
	r := sig.R.XScalar()
	mk := m.Mul(sig.KShare)
	rx := r.Mul(sig.ChiShare)
	sigma := mk.Add(rx)
	return sigma
}

// Signature combines the given shares σⱼ and returns a pair (R,S), where S=∑ⱼσⱼ
func (sig *PreSignature) Signature(shares map[party.ID]SignatureShare) *Signature {
	s := sig.Group.NewScalar()
	for _, sigma := range shares {
		s.Add(sigma)
	}
	return &Signature{
		R: sig.R,
		S: s,
	}
}

// VerifySignatureShares should be called if the signature returned by PreSignature.Signature is not valid.
// It returns the list of parties whose shares are invalid.
func (sig *PreSignature) VerifySignatureShares(shares map[party.ID]SignatureShare, hash []byte) (culprits []party.ID) {
	r := sig.R.XScalar()
	m := curve.FromHash(sig.Group, hash)
	for j, share := range shares {
		Rj, Sj := sig.RBar[j], sig.S[j]
		if Rj == nil || Sj == nil {
			culprits = append(culprits, j)
			continue
		}
		lhs := share.Act(sig.R)
		rhs := m.Act(Rj).Add(r.Act(Sj))
		if !lhs.Equal(rhs) {
			culprits = append(culprits, j)
		}
	}
	return
}
