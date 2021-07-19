package sign

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/protocols/refresh"
)

// LocalParty is the state we store for a remote party.
// The messages are embedded to make access to the attributes easier.
type LocalParty struct {
	*refresh.Public

	DeltaMtA, ChiMtA *MtA

	// K = Kⱼ = encⱼ(kⱼ)
	K *paillier.Ciphertext
	// G = Gⱼ = encⱼ(γⱼ)
	G *paillier.Ciphertext

	// BigGammaShare = Γⱼ = [γⱼ]G
	BigGammaShare *curve.Point

	// DeltaShareMtA = δᵢⱼ = αᵢⱼ + βᵢⱼ
	DeltaShareMtA *curve.Scalar
	// ChiShareMtA = χᵢⱼ = α̂ᵢⱼ +  ̂βᵢⱼ
	ChiShareMtA *curve.Scalar

	// DeltaShare = δⱼ
	DeltaShare *curve.Scalar

	// BigDeltaShare = Δⱼ = [kⱼ]Γⱼ
	BigDeltaShare *curve.Point

	// SigmaShare = σᵢ = kᵢ m + r χᵢ
	SigmaShare *curve.Scalar
}
