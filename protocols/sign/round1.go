package sign

import (
	"fmt"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zkenc "github.com/taurusgroup/cmp-ecdsa/pkg/zk/enc"
)

type round1 struct {
	*round.BaseRound

	thisParty *localParty
	parties   map[party.ID]*localParty

	// gamma = γᵢ <- 𝔽
	gamma *curve.Scalar
	// k = kᵢ  <- 𝔽
	k *curve.Scalar

	// kRand = ρᵢ <- ℤₙ
	// used to encrypt Kᵢ = Encᵢ(kᵢ)
	kRand *big.Int
	// gammaRand = νᵢ <- ℤₙ
	// used to encrypt Gᵢ = Encᵢ(γᵢ)
	gammaRand *big.Int
}

// ProcessMessage implements round.Round
func (round *round1) ProcessMessage(*pb.Message) error {
	// In the first round, no messages are expected.
	return nil
}

// GenerateMessages implements round.Round
//
// - sample kᵢ, γᵢ <- 𝔽,
// - Γᵢ = [γᵢ]⋅G
// - Gᵢ = Encᵢ(γᵢ;νᵢ)
// - Kᵢ = Encᵢ(kᵢ;ρᵢ)
func (round *round1) GenerateMessages() ([]*pb.Message, error) {
	// γᵢ <- 𝔽,
	round.gamma = curve.NewScalarRandom()
	// Γᵢ = [γᵢ]⋅G
	round.thisParty.Gamma = curve.NewIdentityPoint().ScalarBaseMult(round.gamma)
	// Gᵢ = Encᵢ(γᵢ;νᵢ)
	round.thisParty.G, round.gammaRand = round.thisParty.Paillier.Enc(round.gamma.BigInt(), nil)

	// kᵢ <- 𝔽,
	round.k = curve.NewScalarRandom()
	// Kᵢ = Encᵢ(kᵢ;ρᵢ)
	round.thisParty.K, round.kRand = round.thisParty.Paillier.Enc(round.k.BigInt(), nil)

	messages := make([]*pb.Message, 0, round.S.N()-1)

	for j, partyJ := range round.parties {
		if j == round.SelfID {
			continue
		}

		msg1, err := round.message1(partyJ)
		if err != nil {
			return nil, err
		}

		messages = append(messages, msg1)
	}

	return messages, nil
}

func (round *round1) message1(partyJ *localParty) (*pb.Message, error) {
	zkEncPublic := zkenc.Public{
		K:      round.thisParty.K,
		Prover: round.thisParty.Paillier,
		Aux:    partyJ.Pedersen,
	}
	proof, err := zkEncPublic.Prove(round.H.CloneWithID(round.SelfID), zkenc.Private{
		K:   round.k.BigInt(),
		Rho: round.kRand,
	})
	if err != nil {
		return nil, fmt.Errorf("sign.round1.GenerateMessages(): failed to generate enc proof: %w", err)
	}

	// NOTE
	// The protocol instructs us to broadcast Kᵢ and Gᵢ, but the protocol we implement
	// cannot handle identify aborts since we are in a point to point model.
	// We do as described in [LN18].
	//
	// In the next round, we send a hash H of all the {Kⱼ,Gⱼ}ⱼ.
	// In two rounds, we compare the hashes H received and if they are different then we abort.
	return &pb.Message{
		Type: pb.MessageType_TypeSign1,
		From: round.SelfID,
		To:   partyJ.ID,
		Sign1: &pb.Sign1{
			Enc: proof,
			K:   pb.NewCiphertext(round.thisParty.K),
			G:   pb.NewCiphertext(round.thisParty.G),
		},
	}, nil
}

// Finalize implements round.Round
func (round *round1) Finalize() (round.Round, error) {
	return &round2{
		round1:        round,
		hashOfAllKjGj: make([]byte, params.HashBytes),
	}, nil
}

func (round *round1) MessageType() pb.MessageType {
	return pb.MessageType_TypeInvalid
}
