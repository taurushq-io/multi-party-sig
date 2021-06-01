package sign

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zkenc "github.com/taurusgroup/cmp-ecdsa/pkg/zk/enc"
	zklogstar2 "github.com/taurusgroup/cmp-ecdsa/pkg/zk/logstar"
	mta2 "github.com/taurusgroup/cmp-ecdsa/protocols/sign/mta"
)

type round2 struct {
	*round1

	// hashOfAllKjGj = H(K₁, G₁, ..., Kₙ, Gₙ)
	// part of the echo of the first message
	hashOfAllKjGj []byte
}

// ProcessMessage implements round.Round
//
//
func (round *round2) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFromID()
	partyJ := round.parties[j]

	sign1 := msg.GetSign1()

	K := sign1.GetK().Unmarshal()

	public := zkenc.Public{
		K:      K,
		Prover: partyJ.Paillier,
		Aux:    round.thisParty.Pedersen,
	}
	if !public.Verify(round.H.CloneWithID(j), sign1.GetEnc()) {
		return fmt.Errorf("sign.round2.ProcessMessage(): party %s: enc proof failed to verify", j)
	}

	partyJ.K = K
	partyJ.G = sign1.GetG().Unmarshal()

	return partyJ.AddMessage(msg)
}

// GenerateMessages implements round.Round
//
//
func (round *round2) GenerateMessages() ([]*pb.Message, error) {
	// compute H(K₁, G₁, ..., Kₙ, Gₙ)
	if err := round.computeHashKJ(); err != nil {
		return nil, err
	}

	// Broadcast the message we created in round1
	messages := make([]*pb.Message, 0, round.S.N()-1)
	for j, partyJ := range round.parties {
		if j == round.SelfID {
			continue
		}

		partyJ.DeltaMtA = mta2.New(round.gamma, partyJ.K, partyJ.Paillier, round.thisParty.Paillier)
		partyJ.ChiMtA = mta2.New(round.S.Secret.ECDSA, partyJ.K, partyJ.Paillier, round.thisParty.Paillier)

		msg2, err := round.message2(partyJ)
		if err != nil {
			return nil, err
		}

		messages = append(messages, msg2)
	}

	return messages, nil
}

func (round *round2) computeHashKJ() error {
	// The papers says that we need to reliably broadcast this data, however unless we use
	// a system like white-city, we can't actually do this.
	// In the next round, if someone has a different hash, then we must abort, but there is no way of knowing who
	// was the culprit. We could maybe assume that we have an honest majority, but this clashes with the base assumptions.
	h := round.H.Clone()
	for _, id := range round.S.SignerIDs {
		partyJ := round.parties[id]
		if err := h.WriteAny(partyJ.K, partyJ.G); err != nil {
			return fmt.Errorf("sign.round2.GenerateMessages(): hash of K,J: %w", err)
		}
	}
	round.hashOfAllKjGj = make([]byte, params.HashBytes)
	if _, err := h.ReadBytes(round.hashOfAllKjGj); err != nil {
		return fmt.Errorf("sign.round2.GenerateMessages(): hash of K,J: %w", err)
	}
	return nil
}

func (round *round2) message2(partyJ *localParty) (*pb.Message, error) {
	proofDelta, err := partyJ.DeltaMtA.ProveAffG(round.thisParty.Gamma, round.H.CloneWithID(round.SelfID), partyJ.Pedersen)
	if err != nil {
		return nil, fmt.Errorf("sign.round2.GenerateMessages(): failed to generate affg proof: %w", err)
	}
	proofChi, err := partyJ.ChiMtA.ProveAffG(round.thisParty.ECDSA, round.H.CloneWithID(round.SelfID), partyJ.Pedersen)
	if err != nil {
		return nil, fmt.Errorf("sign.round2.GenerateMessages(): failed to generate affg hat proof: %w", err)
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
		return nil, fmt.Errorf("sign.round2.GenerateMessages(): failed to generate log proof: %w", err)
	}

	return &pb.Message{
		Type: pb.MessageType_TypeSign2,
		From: round.SelfID,
		To:   partyJ.ID, Sign2: &pb.Sign2{
			HashKG:       round.hashOfAllKjGj,
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

// Finalize implements round.Round
//
//
func (round *round2) Finalize() (round.Round, error) {
	return &round3{
		round2: round,
	}, nil
}

func (round *round2) MessageType() pb.MessageType {
	return pb.MessageType_TypeSign1
}
