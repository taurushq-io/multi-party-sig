package refresh_threshold

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zkmod "github.com/taurusgroup/cmp-ecdsa/pkg/zk/mod"
	zkprm "github.com/taurusgroup/cmp-ecdsa/pkg/zk/prm"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

type round4 struct {
	*round3
	rho []byte
}

func (round *round4) ProcessMessage(msg *pb.Message) error {
	var err error

	j := msg.GetFromID()
	partyJ := round.parties[j]

	body := msg.GetRefreshT3()

	// Set rho
	rho := body.GetRho()
	if len(rho) != params.SecBytes {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: rho is wrong lenght", j)
	}
	partyJ.rho = rho

	// Save all X, A
	if partyJ.polyExp, err = body.F.Unmarshall(); err != nil {
		return err
	}
	// check that the constant coefficient is 0
	if !partyJ.polyExp.Constant().Equal(curve.NewIdentityPoint()) {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: exponent polynomial has non 0 constant", j)
	}
	// check deg(Fⱼ) = t
	if partyJ.polyExp.Degree() != round.S.Threshold {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: exponent polynomial has wrong degree", j)
	}

	// Save Schnorr commitments
	if partyJ.A, err = pb.UnmarshalPoints(body.GetA()); err != nil {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: unmarshal points: %w", j, err)
	}
	if len(partyJ.A) != round.S.Threshold {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: wrong number of Schnorr commitments", j)
	}

	// Set Paillier
	Nj := body.GetN().Unmarshal()
	if Nj.BitLen() != params.PaillierBits {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: Paillier public key has wrong number of bits", j)
	}
	partyJ.Paillier = paillier.NewPublicKey(Nj)

	// Set Pedersen
	partyJ.Pedersen = &pedersen.Parameters{
		N: Nj,
		S: body.GetS().Unmarshal(),
		T: body.GetT().Unmarshal(),
	}
	if err = partyJ.Pedersen.Validate(); err != nil {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: %w", j, err)
	}

	// Verify decommit
	decommitment := body.GetU()
	if !round.H.Decommit(j, partyJ.commitment, decommitment,
		partyJ.rho, partyJ.polyExp, partyJ.A, partyJ.Pedersen) {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: failed to decommit", j)
	}

	return partyJ.AddMessage(msg)
}

func (round *round4) GenerateMessages() ([]*pb.Message, error) {
	// ρ = ⊕ⱼ ρⱼ
	round.rho = make([]byte, params.SecBytes)
	for _, partyJ := range round.parties {
		for i := 0; i < params.SecBytes; i++ {
			round.rho[i] ^= partyJ.rho[i]
		}
	}

	// Write rho to the hash state
	if _, err := round.H.Write(round.rho); err != nil {
		return nil, fmt.Errorf("refresh.round4.GenerateMessages(): write rho to hash: %w", err)
	}

	partyI := round.thisParty

	skPaillier := round.S.Secret.Paillier

	// Prove N is a blum prime with zkmod
	mod, err := zkmod.Public{N: partyI.Pedersen.N}.Prove(round.H.CloneWithID(round.SelfID), zkmod.Private{
		P:   skPaillier.P,
		Q:   skPaillier.Q,
		Phi: skPaillier.Phi,
	})
	if err != nil {
		return nil, fmt.Errorf("refresh.round4.GenerateMessages(): failed to generate mod proof: %w", err)
	}

	// prove s, t are correct as aux parameters with zkprm
	prm, err := zkprm.Public{Pedersen: partyI.Pedersen}.Prove(round.H.CloneWithID(round.SelfID), zkprm.Private{
		Lambda: round.lambda,
		Phi:    skPaillier.Phi,
	})
	if err != nil {
		return nil, fmt.Errorf("refresh.round4.GenerateMessages(): failed to generate prm proof: %w", err)
	}

	// Compute all ZKPoK Xⱼ = [xⱼ] G
	schXproto := make([]*pb.Scalar, round.S.Threshold)
	var schX *curve.Scalar
	for j := range schXproto {
		x := round.poly.Coefficients()[j+1]
		X := round.thisParty.polyExp.Coefficients()[j+1]
		schX, err = zksch.Prove(round.H.CloneWithID(round.SelfID), partyI.A[j], X, round.schnorrRand[j], x)
		if err != nil {
			return nil, fmt.Errorf("refresh.round4.GenerateMessages(): failed to generate sch proof for coef %d: %w", j, err)
		}
		schXproto[j] = pb.NewScalar(schX)
	}

	// create messages with encrypted shares
	msgs := make([]*pb.Message, 0, round.S.N()-1)
	for _, idJ := range round.S.PartyIDs {
		if idJ == round.SelfID {
			continue
		}

		partyJ := round.parties[idJ]

		// compute fᵢ(idJ)
		index := curve.NewScalar().SetBytes([]byte(idJ))
		share := round.poly.Evaluate(index)
		// Encrypt share
		C, _ := partyJ.Paillier.Enc(share.BigInt(), nil)

		msgs = append(msgs, &pb.Message{
			Type: pb.MessageType_TypeKeygen3,
			From: round.SelfID,
			To:   idJ,
			RefreshT4: &pb.RefreshT4{
				Mod:  mod,
				Prm:  prm,
				C:    pb.NewCiphertext(C),
				SchF: schXproto,
			},
		})
	}

	return msgs, nil
}

func (round *round4) Finalize() (round.Round, error) {
	return &output{
		round4: round,
	}, nil
}

func (round *round4) MessageType() pb.MessageType {
	return pb.MessageType_TypeRefreshThreshold3
}
