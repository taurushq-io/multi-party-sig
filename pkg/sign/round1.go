package sign

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zkenc "github.com/taurusgroup/cmp-ecdsa/pkg/sign/enc"
)

type round1 struct {
	*round.BaseRound

	p         *Parameters
	thisParty *localParty
	parties   map[party.ID]*localParty

	message []byte

	paillier *paillier.SecretKey
	ecdsa    *curve.Scalar

	// gamma = γᵢ
	gamma *curve.Scalar
	// k = kᵢ
	k *curve.Scalar

	// kRand = ρᵢ
	kRand *big.Int
	// gammaRand = νᵢ
	gammaRand *big.Int
}

func (round *round1) ProcessMessage(*pb.Message) error {
	// In the first round, no messages are expected.
	return nil
}

func (round *round1) GenerateMessages() ([]*pb.Message, error) {
	round.gamma = curve.NewScalarRandom()
	round.thisParty.Gamma = curve.NewIdentityPoint().ScalarBaseMult(round.gamma)
	round.thisParty.G, round.gammaRand = round.thisParty.Paillier.Enc(round.gamma.BigInt(), nil)

	round.k = curve.NewScalarRandom()
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
		return nil, err
	}

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

func (round *round1) Finalize() (round.Round, error) {
	return &round2{round}, nil
}

func (round *round1) MessageType() pb.MessageType {
	return pb.MessageType_TypeInvalid
}
