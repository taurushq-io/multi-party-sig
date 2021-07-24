package sign

import (
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zkenc "github.com/taurusgroup/cmp-ecdsa/pkg/zk/enc"
	"github.com/taurusgroup/cmp-ecdsa/protocols/cmp/keygen"
)

var _ round.Round = (*round1)(nil)

type round1 struct {
	*round.Helper

	Secret *keygen.Secret

	PublicKey *ecdsa.PublicKey

	Public map[party.ID]*keygen.Public

	Message []byte
}

// ProcessMessage implements round.Round
func (r *round1) ProcessMessage(party.ID, message.Content) error { return nil }

// Finalize implements round.Round
//
// - sample kᵢ, γᵢ <- 𝔽,
// - Γᵢ = [γᵢ]⋅G
// - Gᵢ = Encᵢ(γᵢ;νᵢ)
// - Kᵢ = Encᵢ(kᵢ;ρᵢ)
//
// NOTE
// The protocol instructs us to broadcast Kᵢ and Gᵢ, but the protocol we implement
// cannot handle identify aborts since we are in a point to point model.
// We do as described in [LN18].
//
// In the next round, we send a hash of all the {Kⱼ,Gⱼ}ⱼ.
// In two rounds, we compare the hashes received and if they are different then we abort.
func (r *round1) Finalize(out chan<- *message.Message) (round.Round, error) {
	// γᵢ <- 𝔽,
	// Γᵢ = [γᵢ]⋅G
	GammaShare, BigGammaShare := sample.ScalarPointPair(rand.Reader)
	// Gᵢ = Encᵢ(γᵢ;νᵢ)
	G, GNonce := r.Public[r.SelfID()].Paillier.Enc(GammaShare.Int())

	// kᵢ <- 𝔽,
	KShare := sample.Scalar(rand.Reader)
	// Kᵢ = Encᵢ(kᵢ;ρᵢ)
	K, KNonce := r.Public[r.SelfID()].Paillier.Enc(KShare.Int())

	for _, j := range r.OtherPartyIDs() {
		proof := zkenc.NewProof(r.HashForID(r.SelfID()), zkenc.Public{
			K:      K,
			Prover: r.Public[r.SelfID()].Paillier,
			Aux:    r.Public[j].Pedersen,
		}, zkenc.Private{
			K:   KShare.Int(),
			Rho: KNonce,
		})

		// ignore error
		msg := r.MarshalMessage(&Sign2{
			ProofEnc: proof,
			K:        K,
			G:        G,
		}, j)
		if err := r.SendMessage(msg, out); err != nil {
			return r, err
		}
	}

	return &round2{
		round1:        r,
		K:             map[party.ID]*paillier.Ciphertext{r.SelfID(): K},
		G:             map[party.ID]*paillier.Ciphertext{r.SelfID(): G},
		BigGammaShare: map[party.ID]*curve.Point{r.SelfID(): BigGammaShare},
		GammaShare:    GammaShare,
		KShare:        KShare,
		KNonce:        KNonce,
		GNonce:        GNonce,
	}, nil
}

// MessageContent implements round.Round
func (r *round1) MessageContent() message.Content { return &message.First{} }
