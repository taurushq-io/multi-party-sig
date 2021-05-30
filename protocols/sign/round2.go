package sign

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zkenc2 "github.com/taurusgroup/cmp-ecdsa/pkg/zk/enc"
	zklogstar2 "github.com/taurusgroup/cmp-ecdsa/pkg/zk/logstar"
	mta2 "github.com/taurusgroup/cmp-ecdsa/protocols/sign/mta"
)

type round2 struct {
	*round1
}

func (round *round2) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFrom()
	partyJ := round.parties[j]

	sign1 := msg.GetSign1()

	K := sign1.GetK().Unmarshal()

	public := zkenc2.Public{
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
	messages := make([]*pb.Message, 0, round.S.N()-1)
	for j, partyJ := range round.parties {
		if j == round.SelfID {
			continue
		}

		partyJ.DeltaMtA = mta2.New(round.gamma, partyJ.K, partyJ.Paillier, round.thisParty.Paillier)
		partyJ.ChiMtA = mta2.New(round.Secret.ECDSA, partyJ.K, partyJ.Paillier, round.thisParty.Paillier)

		msg2, err := round.message2(partyJ)
		if err != nil {
			return nil, err
		}

		messages = append(messages, msg2)
	}

	return messages, nil
}

func (round *round2) message2(partyJ *localParty) (*pb.Message, error) {
	proofDelta, err := partyJ.DeltaMtA.ProveAffG(round.thisParty.Gamma, round.H.CloneWithID(round.SelfID), partyJ.Pedersen)
	if err != nil {
		return nil, err
	}
	proofChi, err := partyJ.ChiMtA.ProveAffG(round.thisParty.ECDSA, round.H.CloneWithID(round.SelfID), partyJ.Pedersen)
	if err != nil {
		return nil, err
	}

	proofLog, err := zklogstar2.Public{
		C:      round.thisParty.G,
		X:      round.thisParty.Gamma,
		Prover: round.thisParty.Paillier,
		Aux:    partyJ.Pedersen,
	}.Prove(round.H.CloneWithID(round.SelfID), zklogstar2.Private{
		X:   round.gamma.BigInt(),
		Rho: round.gammaRand,
	})
	if err != nil {
		return nil, err
	}

	return &pb.Message{
		Type: pb.MessageType_TypeSign2,
		From: round.SelfID,
		To:   partyJ.ID, Sign2: &pb.Sign2{
			Gamma:        pb.NewPoint(round.thisParty.Gamma),
			D:            pb.NewCiphertext(partyJ.DeltaMtA.D),
			F:            pb.NewCiphertext(partyJ.DeltaMtA.F),
			DHat:         pb.NewCiphertext(partyJ.ChiMtA.D),
			FHat:         pb.NewCiphertext(partyJ.ChiMtA.F),
			ProofAffG:    proofDelta,
			ProofAffGHat: proofChi,
			ProofLog:     proofLog,
		},
	}, nil
}

func (round *round2) Finalize() (round.Round, error) {
	return &round3{
		round2: round,
	}, nil
}

func (round *round2) MessageType() pb.MessageType {
	return pb.MessageType_TypeSign1
}
