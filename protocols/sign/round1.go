package sign

import (
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zkenc "github.com/taurusgroup/cmp-ecdsa/pkg/zk/enc"
)

type round1 struct {
	*round.BaseRound

	Self    *LocalParty
	parties map[party.ID]*LocalParty
	Secret  *party.Secret

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
func (r *round1) ProcessMessage(round.Message) error {
	// In the first round, no messages are expected.
	return nil
}

// GenerateMessages implements round.Round
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
func (r *round1) GenerateMessages() ([]round.Message, error) {
	// γᵢ <- 𝔽,
	// Γᵢ = [γᵢ]⋅G
	r.GammaShare, r.Self.BigGammaShare = sample.ScalarPointPair(rand.Reader)
	// Gᵢ = Encᵢ(γᵢ;νᵢ)
	r.Self.G, r.GNonce = r.Self.Paillier.Enc(r.GammaShare.BigInt())

	// kᵢ <- 𝔽,
	r.KShare = sample.Scalar(rand.Reader)
	// Kᵢ = Encᵢ(kᵢ;ρᵢ)
	r.Self.K, r.KNonce = r.Self.Paillier.Enc(r.KShare.BigInt())

	messages := make([]round.Message, 0, r.S.N()-1)

	for j, partyJ := range r.parties {
		if j == r.SelfID {
			continue
		}

		proof := zkenc.NewProof(r.Hash.CloneWithID(r.SelfID), zkenc.Public{
			K:      r.Self.K,
			Prover: r.Self.Paillier,
			Aux:    partyJ.Pedersen,
		}, zkenc.Private{
			K:   r.KShare.BigInt(),
			Rho: r.KNonce,
		})

		msg1 := NewMessageSign1(r.SelfID, j, &Sign1{
			ProofEnc: proof,
			K:        r.Self.K,
			G:        r.Self.G,
		})

		messages = append(messages, msg1)
	}

	return messages, nil
}

// Finalize implements round.Round
func (r *round1) Finalize() (round.Round, error) {
	r.Next()
	return &round2{
		round1: r,
	}, nil
}

func (r *round1) ExpectedMessageID() round.MessageID {
	return round.MessageIDInvalid
}
