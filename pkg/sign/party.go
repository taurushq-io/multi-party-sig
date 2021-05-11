package sign

import (
	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
	"github.com/taurusgroup/cmp-ecdsa/pkg/sign/mta"
)

// localParty is the state we store for a remote party.
// The messages are embedded to make access to the attributes easier.
type localParty struct {
	*round.Party

	Paillier *paillier.PublicKey
	Pedersen *pedersen.Parameters
	ECDSA    *curve.Point

	DeltaMtA *mta.MtA
	ChiMtA   *mta.MtA

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

	sign1 *pb.Sign1
	sign2 *pb.Sign2
	sign3 *pb.Sign3
	sign4 *pb.Sign4
}

func newParty(id party.ID, public *session.Public) *localParty {
	return &localParty{
		Party:    round.NewBaseParty(id),
		Paillier: public.Paillier(),
		Pedersen: public.Pedersen(),
		ECDSA:    public.ShareECDSA(),
	}
}
