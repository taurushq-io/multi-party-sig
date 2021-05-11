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

func (round *round1) ProcessMessage(msg *pb.Message) error {
	// In the first round, no messages are expected.
	return nil
}

func (round *round1) GenerateMessages() ([]*pb.Message, error) {
	round.gamma = curve.NewScalarRandom()
	round.k = curve.NewScalarRandom()
	round.thisParty.K, round.kRand = round.thisParty.Paillier.Enc(round.k.BigInt(), nil)
	round.thisParty.G, round.gammaRand = round.thisParty.Paillier.Enc(round.gamma.BigInt(), nil)

	round.thisParty.Gamma = curve.NewIdentityPoint().ScalarBaseMult(round.gamma)

	messages := make([]*pb.Message, 0, round.S.N()-1)

	zkEncPublic := zkenc.Public{
		K:      round.thisParty.K,
		Prover: round.thisParty.Paillier,
	}
	zkEncPrivate := zkenc.Private{
		K:   round.k.BigInt(),
		Rho: round.kRand,
	}
	for j, partyJ := range round.parties {
		if j == round.SelfID {
			continue
		}
		zkEncPublic.Aux = partyJ.Pedersen

		proof, err := zkEncPublic.Prove(round.H.CloneWithID(round.SelfID), zkEncPrivate)
		if err != nil {
			return nil, err
		}
		messages = append(messages, &pb.Message{
			Type: pb.MessageType_TypeSign1,
			From: round.SelfID,
			To:   j,
			Content: &pb.Message_Sign1{
				Sign1: &pb.Sign1{
					K:   pb.NewCiphertext(round.thisParty.K),
					G:   pb.NewCiphertext(round.thisParty.G),
					Enc: proof,
				},
			},
		})
	}

	return messages, nil
}

func (round *round1) Finalize() (round.Round, error) {
	return &round2{round}, nil
}

func (round *round1) MessageType() pb.MessageType {
	return pb.MessageType_TypeInvalid
}

func (round *round1) RequiredMessageCount() int {
	return round.S.N()
}
func (round *round1) IsProcessed(id party.ID) bool {
	return true
}
