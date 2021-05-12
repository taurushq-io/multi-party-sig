package sign

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zkaffg "github.com/taurusgroup/cmp-ecdsa/pkg/sign/affg"
	zklogstar "github.com/taurusgroup/cmp-ecdsa/pkg/sign/logstar"
)

type round3 struct {
	*round2
	// Gamma = ∑ᵢ Γᵢ
	Gamma *curve.Point

	// chi = χⱼ
	chi *curve.Scalar
}

func (round *round3) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFrom()
	partyJ, ok := round.parties[j]
	if !ok {
		return errors.New("sender not registered")
	}
	body := msg.GetSign2()

	gamma, err := body.Gamma.Unmarshal()
	if err != nil {
		return err
	}

	D := body.D.Unmarshal()
	DHat := body.DHat.Unmarshal()

	zkAffgPublic := zkaffg.Public{
		C:        round.thisParty.K,
		D:        D,
		Y:        body.F.Unmarshal(),
		X:        gamma,
		Prover:   partyJ.Paillier,
		Verifier: round.thisParty.Paillier,
		Aux:      round.thisParty.Pedersen,
	}
	if !zkAffgPublic.Verify(round.H.CloneWithID(j), body.ProofAffG) {
		return errors.New("zkaffg failed")
	}

	zkAffgPublicHat := zkaffg.Public{
		C:        round.thisParty.K,
		D:        DHat,
		Y:        body.FHat.Unmarshal(),
		X:        partyJ.ECDSA,
		Prover:   partyJ.Paillier,
		Verifier: round.thisParty.Paillier,
		Aux:      round.thisParty.Pedersen,
	}
	if !zkAffgPublicHat.Verify(round.H.CloneWithID(j), body.ProofAffGHat) {
		return errors.New("zkaffghat failed")
	}

	zkLogPublic := zklogstar.Public{
		C:      partyJ.G,
		X:      gamma,
		Prover: partyJ.Paillier,
		Aux:    round.thisParty.Pedersen,
	}
	if !zkLogPublic.Verify(round.H.CloneWithID(j), body.ProofLog) {
		return errors.New("zklog r3 failed")
	}

	partyJ.Gamma = gamma
	partyJ.ShareAlphaDelta = curve.NewScalarBigInt(round.paillier.Dec(D))
	partyJ.ShareAlphaChi = curve.NewScalarBigInt(round.paillier.Dec(DHat))

	return partyJ.AddMessage(msg)
}

func (round *round3) GenerateMessages() ([]*pb.Message, error) {
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

	messages := make([]*pb.Message, 0, round.S.N()-1)
	for j, partyJ := range round.parties {
		if j == round.SelfID {
			continue
		}

		msg, err := round.message3(partyJ)
		if err != nil {
			return nil, err
		}

		messages = append(messages, msg)
	}

	return messages, nil
}

func (round *round3) message3(partyJ *localParty) (*pb.Message, error) {
	proofLog, err := zklogstar.Public{
		C:      round.thisParty.K,
		X:      round.thisParty.Delta,
		G:      round.Gamma,
		Prover: round.thisParty.Paillier,
		Aux:    partyJ.Pedersen,
	}.Prove(round.H.CloneWithID(round.SelfID), zklogstar.Private{
		X:   round.k.BigInt(),
		Rho: round.kRand,
	})
	if err != nil {
		return nil, err
	}

	return &pb.Message{
		Type: pb.MessageType_TypeSign3,
		From: round.SelfID,
		To:   partyJ.ID,
		Content: &pb.Message_Sign3{Sign3: &pb.Sign3{
			Delta:      pb.NewScalar(round.thisParty.delta),
			DeltaGroup: pb.NewPoint(round.thisParty.Delta),
			ProofLog:   proofLog,
		}},
	}, nil
}

func (round *round3) Finalize() (round.Round, error) {
	return &round4{
		round3: round,
	}, nil
}

func (round *round3) MessageType() pb.MessageType {
	return pb.MessageType_TypeSign2
}

func (round *round3) RequiredMessageCount() int {
	return round.S.N() - 1
}

func (round *round3) IsProcessed(id party.ID) bool {
	panic("implement me")
}
