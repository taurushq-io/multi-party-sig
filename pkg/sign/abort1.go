package sign

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zklogstar "github.com/taurusgroup/cmp-ecdsa/pkg/sign/logstar"
)

type abort1 struct {
	*round4
}

func (round *abort1) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFrom()
	partyJ, ok := round.parties[j]
	if !ok {
		return errors.New("sender not registered")
	}
	body := msg.GetSign3()

	Delta, err := body.DeltaGroup.Unmarshal()
	if err != nil {
		return err
	}

	zkLogPublic := zklogstar.Public{
		C:      partyJ.K,
		X:      Delta,
		G:      round.Gamma,
		Prover: partyJ.Paillier,
		Aux:    round.thisParty.Pedersen,
	}

	if !zkLogPublic.Verify(round.H.CloneWithID(j), body.ProofLog) {
		return errors.New("zklog failed")
	}

	partyJ.Delta = Delta
	partyJ.delta = body.GetDelta().Unmarshal()

	return partyJ.AddMessage(msg)
}

func (round *abort1) GenerateMessages() ([]*pb.Message, error) {
	// Γ = ∑ⱼ Γⱼ
	round.Gamma = curve.NewIdentityPoint()
	for _, partyJ := range round.parties {
		round.Gamma.Add(round.Gamma, partyJ.Gamma)
	}

	// Δᵢ = [kᵢ]Γ
	round.thisParty.Delta = curve.NewIdentityPoint().ScalarMult(round.k, round.Gamma)

	// δᵢ = γᵢ kᵢ
	round.thisParty.delta = curve.NewScalar().Multiply(round.gamma, round.k)

	// χᵢ = xᵢ kᵢ
	round.chi = curve.NewScalar().Multiply(round.ecdsa, round.k)

	for j, partyJ := range round.parties {
		if j == round.SelfID {
			continue
		}
		// δᵢ += αᵢⱼ + βᵢⱼ
		round.thisParty.delta.Add(round.thisParty.delta, partyJ.ShareAlphaDelta)
		round.thisParty.delta.Add(round.thisParty.delta, partyJ.DeltaMtA.Beta)

		// χᵢ += α̂ᵢⱼ  ̂βᵢⱼ
		round.chi.Add(round.chi, partyJ.ShareAlphaChi)
		round.chi.Add(round.chi, partyJ.ChiMtA.Beta)
	}

	zkLogPublic := zklogstar.Public{
		C:      round.thisParty.K,
		X:      round.thisParty.Delta,
		G:      round.Gamma,
		Prover: round.thisParty.Paillier,
	}
	zkLogPrivate := zklogstar.Private{
		X:   round.k.BigInt(),
		Rho: round.kRand,
	}
	messages := make([]*pb.Message, 0, round.S.N()-1)
	for j, partyJ := range round.parties {
		if j == round.SelfID {
			continue
		}

		zkLogPublic.Aux = partyJ.Pedersen
		proofLog, err := zkLogPublic.Prove(round.H.CloneWithID(round.SelfID), zkLogPrivate)
		if err != nil {
			return nil, err
		}

		msg := &pb.Message{
			Type: pb.MessageType_TypeSign3,
			From: round.SelfID,
			To:   j,
			Content: &pb.Message_Sign3{Sign3: &pb.Sign3{
				Delta:      pb.NewScalar(round.thisParty.delta),
				DeltaGroup: pb.NewPoint(round.thisParty.Delta),
				ProofLog:   proofLog,
			}},
		}
		messages = append(messages, msg)
	}

	return messages, nil
}

func (round *abort1) Finalize() (round.Round, error) {
	return &output{
		//abort1: round,
	}, nil
}

func (round *abort1) MessageType() pb.MessageType {
	return pb.MessageType_TypeSign3
}

func (round *abort1) RequiredMessageCount() int {
	return round.S.N() - 1
}

func (round *abort1) IsProcessed(id party.ID) bool {
	panic("implement me")
}
