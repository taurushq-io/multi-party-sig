package sign

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	mta2 "github.com/taurusgroup/cmp-ecdsa/protocols/sign/mta"
)

// localParty is the state we store for a remote party.
// The messages are embedded to make access to the attributes easier.
type localParty struct {
	*round.Party

	DeltaMtA *mta2.MtA
	ChiMtA   *mta2.MtA

	// K = Kⱼ = encⱼ(kⱼ)
	K *paillier.Ciphertext
	// G = Gⱼ = encⱼ(γⱼ)
	G *paillier.Ciphertext

	// Gamma = Γⱼ = [γⱼ]G
	Gamma *curve.Point

	// Delta = Δⱼ = [kⱼ]Γⱼ
	Delta *curve.Point

	// delta = δⱼ
	delta *curve.Scalar

	// ShareAlphaDelta = αᵢⱼ
	ShareAlphaDelta *curve.Scalar
	// ShareAlphaDelta = α̂ᵢⱼ
	ShareAlphaChi *curve.Scalar

	// sigma = σᵢ = kᵢ m + r χᵢ
	sigma *curve.Scalar
}
