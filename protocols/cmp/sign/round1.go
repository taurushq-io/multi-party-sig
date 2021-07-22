package sign

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zkenc "github.com/taurusgroup/cmp-ecdsa/pkg/zk/enc"
	"github.com/taurusgroup/cmp-ecdsa/protocols/cmp/keygen"
)

type round1 struct {
	*round.Helper

	Self *LocalParty

	Secret *keygen.Secret

	PublicKey *ecdsa.PublicKey

	Parties map[party.ID]*LocalParty

	SignerIDs party.IDSlice

	// GammaShare = γᵢ <- 𝔽
	GammaShare *curve.Scalar
	// KShare = kᵢ  <- 𝔽
	KShare *curve.Scalar

	// KNonce = ρᵢ <- ℤₙ
	// used to encrypt Kᵢ = Encᵢ(kᵢ)
	KNonce *big.Int
	// GNonce = νᵢ <- ℤₙ
	// used to encrypt Gᵢ = Encᵢ(γᵢ)
	GNonce *big.Int

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
	r.GammaShare, r.Self.BigGammaShare = sample.ScalarPointPair(rand.Reader)
	// Gᵢ = Encᵢ(γᵢ;νᵢ)
	r.Self.G, r.GNonce = r.Self.Paillier.Enc(r.GammaShare.BigInt())

	// kᵢ <- 𝔽,
	r.KShare = sample.Scalar(rand.Reader)
	// Kᵢ = Encᵢ(kᵢ;ρᵢ)
	r.Self.K, r.KNonce = r.Self.Paillier.Enc(r.KShare.BigInt())

	for j, partyJ := range r.Parties {
		if j == r.Self.ID {
			continue
		}

		proof := zkenc.NewProof(r.HashForID(r.Self.ID), zkenc.Public{
			K:      r.Self.K,
			Prover: r.Self.Paillier,
			Aux:    partyJ.Pedersen,
		}, zkenc.Private{
			K:   r.KShare.BigInt(),
			Rho: r.KNonce,
		})

		// ignore error
		msg := r.MarshalMessage(&Sign2{
			ProofEnc: proof,
			K:        r.Self.K,
			G:        r.Self.G,
		}, j)
		if err := r.SendMessage(msg, out); err != nil {
			return nil, err
		}
	}

	return &round2{round1: r}, nil
}

// MessageContent implements round.Round
func (r *round1) MessageContent() message.Content { return &message.First{} }
