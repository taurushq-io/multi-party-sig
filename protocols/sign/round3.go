package sign

import (
	"bytes"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zkaffg2 "github.com/taurusgroup/cmp-ecdsa/pkg/zk/affg"
	zklogstar2 "github.com/taurusgroup/cmp-ecdsa/pkg/zk/logstar"
)

type round3 struct {
	*round2
	// Gamma = ∑ᵢ Γᵢ
	Gamma *curve.Point

	// chi = χⱼ
	chi *curve.Scalar
}

// ProcessMessage implements round.Round
//
//
func (round *round3) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFromID()
	partyJ := round.parties[j]

	body := msg.GetSign2()

	if !bytes.Equal(body.HashKG, round.hashOfAllKjGj) {
		return fmt.Errorf("sign.round3.ProcessMessage(): party %s: provided hash is different", j)
	}

	gamma, err := body.Gamma.Unmarshal()
	if err != nil {
		return fmt.Errorf("sign.round3.ProcessMessage(): party %s: unmarshal gamma: %w", j, err)
	}

	D := body.D.Unmarshal()
	DHat := body.DHat.Unmarshal()

	zkAffgPublic := zkaffg2.Public{
		C:        round.thisParty.K,
		D:        D,
		Y:        body.F.Unmarshal(),
		X:        gamma,
		Prover:   partyJ.Paillier,
		Verifier: round.thisParty.Paillier,
		Aux:      round.thisParty.Pedersen,
	}
	if !zkAffgPublic.Verify(round.H.CloneWithID(j), body.ProofAffG) {
		return fmt.Errorf("sign.round3.ProcessMessage(): party %s: affg proof failed to verify", j)
	}

	zkAffgPublicHat := zkaffg2.Public{
		C:        round.thisParty.K,
		D:        DHat,
		Y:        body.FHat.Unmarshal(),
		X:        partyJ.ECDSA,
		Prover:   partyJ.Paillier,
		Verifier: round.thisParty.Paillier,
		Aux:      round.thisParty.Pedersen,
	}
	if !zkAffgPublicHat.Verify(round.H.CloneWithID(j), body.ProofAffGHat) {
		return fmt.Errorf("sign.round3.ProcessMessage(): party %s: affg hat proof failed to verify", j)
	}

	zkLogPublic := zklogstar2.Public{
		C:      partyJ.G,
		X:      gamma,
		Prover: partyJ.Paillier,
		Aux:    round.thisParty.Pedersen,
	}
	if !zkLogPublic.Verify(round.H.CloneWithID(j), body.ProofLog) {
		return fmt.Errorf("sign.round3.ProcessMessage(): party %s: log proof failed to verify", j)
	}

	partyJ.Gamma = gamma

	shareAlphaDeltaInt := round.S.Secret.Paillier.Dec(D)
	shareAlphaDelta := curve.NewScalarBigInt(shareAlphaDeltaInt)
	//if shareAlphaDeltaInt.Cmp(shareAlphaDelta.BigInt()) != 0 {
	//	return fmt.Errorf("refresh_old.round3.ProcessMessage(): party %s: decrypted share alpha for delta is not in correct range", j)
	//}
	partyJ.ShareAlphaDelta = shareAlphaDelta

	shareAlphaChiInt := round.S.Secret.Paillier.Dec(DHat)
	shareAlphaChi := curve.NewScalarBigInt(shareAlphaChiInt)
	//if shareAlphaChiInt.Cmp(shareAlphaChi.BigInt()) != 0 {
	//	return fmt.Errorf("refresh_old.round3.ProcessMessage(): party %s: decrypted share alpha for chi is not in correct range", j)
	//}
	partyJ.ShareAlphaChi = shareAlphaChi

	return partyJ.AddMessage(msg)
}

// GenerateMessages implements round.Round
//
//
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
	round.chi = curve.NewScalar().Multiply(round.S.Secret.ECDSA, round.k)

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
	proofLog, err := zklogstar2.Public{
		C:      round.thisParty.K,
		X:      round.thisParty.Delta,
		G:      round.Gamma,
		Prover: round.thisParty.Paillier,
		Aux:    partyJ.Pedersen,
	}.Prove(round.H.CloneWithID(round.SelfID), zklogstar2.Private{
		X:   round.k.BigInt(),
		Rho: round.kRand,
	})
	if err != nil {
		return nil, fmt.Errorf("sign.round3.GenerateMessages(): failed to generate log proof: %w", err)
	}

	return &pb.Message{
		Type: pb.MessageType_TypeSign3,
		From: round.SelfID,
		To:   partyJ.ID, Sign3: &pb.Sign3{
			Delta:      pb.NewScalar(round.thisParty.delta),
			DeltaGroup: pb.NewPoint(round.thisParty.Delta),
			ProofLog:   proofLog,
		},
	}, nil
}

// Finalize implements round.Round
//
//
func (round *round3) Finalize() (round.Round, error) {
	return &round4{
		round3: round,
	}, nil
}

func (round *round3) MessageType() pb.MessageType {
	return pb.MessageType_TypeSign2
}
