package sign

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zkenc "github.com/taurusgroup/cmp-ecdsa/pkg/sign/enc"
	zklogstar "github.com/taurusgroup/cmp-ecdsa/pkg/sign/logstar"
	"github.com/taurusgroup/cmp-ecdsa/pkg/sign/mta"
)

type round2 struct {
	*round1
}

func (round *round2) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFrom()
	partyJ, ok := round.parties[j]
	if !ok {
		return errors.New("sender not registered")
	}

	sign1 := msg.GetSign1()

	K := sign1.GetK().Unmarshal()

	public := zkenc.Public{
		K:      K,
		Prover: partyJ.Paillier,
		Aux:    round.thisParty.Pedersen,
	}
	if !public.Verify(round.H.CloneWithID(j), sign1.GetEnc()) {
		return errors.New("failed enc")
	}

	partyJ.K = K
	partyJ.G = sign1.GetG().Unmarshal()

	return partyJ.AddMessage(msg)
}

func (round *round2) GenerateMessages() ([]*pb.Message, error) {
	// Broadcast the message we created in round1

	zkLogPublic := zklogstar.Public{
		C:      round.thisParty.G,
		X:      round.thisParty.Gamma,
		Prover: round.thisParty.Paillier,
	}

	zkLogPrivate := zklogstar.Private{
		X:   round.gamma.BigInt(),
		Rho: round.gammaRand,
	}

	messages := make([]*pb.Message, 0, round.S.N()-1)
	for j, partyJ := range round.parties {
		if j == round.SelfID {
			continue
		}
		partyJ.DeltaMtA = mta.New(round.gamma, partyJ.K, partyJ.Paillier, round.thisParty.Paillier)
		partyJ.ChiMtA = mta.New(round.ecdsa, partyJ.K, partyJ.Paillier, round.thisParty.Paillier)
		proofDelta, err := partyJ.DeltaMtA.ProveAffG(round.thisParty.Gamma, round.H.CloneWithID(round.SelfID), partyJ.Pedersen)
		if err != nil {
			return nil, err
		}
		proofChi, err := partyJ.ChiMtA.ProveAffG(round.thisParty.ECDSA, round.H.CloneWithID(round.SelfID), partyJ.Pedersen)
		if err != nil {
			return nil, err
		}

		zkLogPublic.Aux = partyJ.Pedersen
		proofLog, err := zkLogPublic.Prove(round.H.CloneWithID(round.SelfID), zkLogPrivate)
		if err != nil {
			return nil, err
		}

		msg := &pb.Message{
			Type: pb.MessageType_TypeSign2,
			From: round.SelfID,
			To:   j,
			Content: &pb.Message_Sign2{Sign2: &pb.Sign2{
				Gamma:        pb.NewPoint(round.thisParty.Gamma),
				D:            pb.NewCiphertext(partyJ.DeltaMtA.D),
				F:            pb.NewCiphertext(partyJ.DeltaMtA.F),
				DHat:         pb.NewCiphertext(partyJ.ChiMtA.D),
				FHat:         pb.NewCiphertext(partyJ.ChiMtA.F),
				ProofAffG:    proofDelta,
				ProofAffGHat: proofChi,
				ProofLog:     proofLog,
			}},
		}
		messages = append(messages, msg)
	}

	return messages, nil
}

func (round *round2) Finalize() (round.Round, error) {
	return &round3{
		round2: round,
	}, nil
}

func (round *round2) MessageType() pb.MessageType {
	return pb.MessageType_TypeSign1
}

func (round *round2) RequiredMessageCount() int {
	return round.S.N() - 1
}

func (round *round2) IsProcessed(id party.ID) bool {
	panic("")
	return true
}

//func (round *round1) NextRound() state.Round {
//	return &round2{round}
//}
