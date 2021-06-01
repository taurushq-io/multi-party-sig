package refresh

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

// ProcessMessage implements round.Round
//
// - store Fⱼ(X)
//   - if keygen, verify Fⱼ(0) != ∞
//   - if refresh, verify Fⱼ(0) == ∞
// - verify length of Schnorr commitments
// - validate Paillier
// - validate Pedersen
// - validate commitments
func (round *round4) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFromID()
	partyJ := round.parties[j]

	body := msg.GetRefresh3()

	// Set rho
	rho := body.GetRho()
	if len(rho) != params.SecBytes {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: rho is wrong lenght", j)
	}

	// Save all X, A
	polyExp, err := body.F.Unmarshall()
	if err != nil {
		return err
	}
	// check that the constant coefficient is 0
	if !round.keygen && !polyExp.Constant().Equal(curve.NewIdentityPoint()) {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: exponent polynomial has non 0 constant", j)
	}
	// check deg(Fⱼ) = t
	if polyExp.Degree() != round.S.Threshold {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: exponent polynomial has wrong degree", j)
	}

	// Save Schnorr commitments
	A, err := pb.UnmarshalPoints(body.GetA())
	if err != nil {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: unmarshal points: %w", j, err)
	}
	if len(A) != len(polyExp.Coefficients()) {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: wrong number of Schnorr commitments", j)
	}

	// Set Paillier
	Nj := body.GetN().Unmarshal()
	paillierPublicKey := paillier.NewPublicKey(Nj)
	if err = paillierPublicKey.Validate(); err != nil {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: %w", j, err)
	}

	// Set Pedersen
	ped := &pedersen.Parameters{
		N: Nj,
		S: body.GetS().Unmarshal(),
		T: body.GetT().Unmarshal(),
	}
	if err = ped.Validate(); err != nil {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: %w", j, err)
	}

	// Verify decommit
	decommitment := body.GetU()
	if !round.H.Decommit(j, partyJ.commitment, decommitment,
		rho, partyJ.polyExp, A, ped) {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: failed to decommit", j)
	}

	partyJ.rho = rho
	partyJ.Pedersen = ped
	partyJ.Paillier = paillierPublicKey
	partyJ.polyExp = polyExp
	partyJ.A = A
	return partyJ.AddMessage(msg)
}

// GenerateMessages implements round.Round
//
// - set ρ = ⊕ⱼ ρⱼ and update hash state
//   - if keygen, write this to the session
// - prove Nᵢ is Blum
// - prove Pedersen parameters
// - prove Schnorr for all coefficients of fᵢ(X)
//   - if refresh skip constant coefficient
//
// - send proofs and encryption of share for Pⱼ
func (round *round4) GenerateMessages() ([]*pb.Message, error) {
	// ρ = ⊕ⱼ ρⱼ
	round.rho = make([]byte, params.SecBytes)
	for _, partyJ := range round.parties {
		for i := 0; i < params.SecBytes; i++ {
			round.rho[i] ^= partyJ.rho[i]
		}
	}
	// set RID if we are in keygen
	if round.keygen {
		round.S.Secret.RID = append([]byte{}, round.rho...)
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
	schXproto := make([]*pb.Scalar, round.S.Threshold+1)
	var schX *curve.Scalar
	for j := range schXproto {
		// skip the first index in keygen mode
		if !round.keygen && j == 0 {
			schXproto[j] = pb.NewScalar(curve.NewScalar())
			continue
		}
		x := round.poly.Coefficients()[j]
		X := round.thisParty.polyExp.Coefficients()[j]
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
			Type: pb.MessageType_TypeRefresh4,
			From: round.SelfID,
			To:   idJ,
			Refresh4: &pb.Refresh4{
				Mod:  mod,
				Prm:  prm,
				C:    pb.NewCiphertext(C),
				SchF: schXproto,
			},
		})
	}

	return msgs, nil
}

// Finalize implements round.Round
func (round *round4) Finalize() (round.Round, error) {
	return &output{
		round4: round,
	}, nil
}

func (round *round4) MessageType() pb.MessageType {
	return pb.MessageType_TypeRefresh3
}
