package keygen_threshold

import (
	"errors"

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
		return errors.New("rho is wrong length")
	}
	partyJ.rho = rho

	// Save all X, A
	if partyJ.polyExp, err = body.F.Unmarshall(); err != nil {
		return err
	}
	// check that the constant coefficient is 0
	if !partyJ.polyExp.Constant().Equal(curve.NewIdentityPoint()) {
		return errors.New("exponent polynomial has constant coefficient != Id")
	}
	// check deg(Fⱼ) = t
	if partyJ.polyExp.Degree() != round.S.Threshold {
		return errors.New("exponent polynomial has wrong degree")
	}

	// Save Schnorr commitments
	if partyJ.A, err = pb.UnmarshalPoints(body.GetA()); err != nil {
		return err
	}
	if len(partyJ.A) != round.S.Threshold {
		return errors.New("wrong number of Schnorr commitments")
	}

	// Set Paillier
	Nj := body.GetN().Unmarshal()
	if Nj.BitLen() != params.PaillierBits {
		return errors.New("N is the wrong number of bits")
	}
	partyJ.Paillier = paillier.NewPublicKey(Nj)

	// Set Pedersen
	partyJ.Pedersen = &pedersen.Parameters{
		N: Nj,
		S: body.GetS().Unmarshal(),
		T: body.GetT().Unmarshal(),
	}
	if !partyJ.Pedersen.IsValid() {
		return errors.New("pedersen invalid")
	}

	// Verify decommit
	decommitment := body.GetU()
	if !round.H.Decommit(j, partyJ.commitment, decommitment,
		partyJ.rho, partyJ.polyExp, partyJ.A, partyJ.Pedersen) {
		return errors.New("failed to decommit")
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
		return nil, err
	}

	partyI := round.thisParty

	// Prove N is a blum prime with zkmod
	mod, err := zkmod.Public{N: partyI.Pedersen.N}.Prove(round.H.CloneWithID(round.SelfID), zkmod.Private{
		P:   round.p,
		Q:   round.q,
		Phi: round.phi,
	})
	if err != nil {
		return nil, err
	}

	// prove s, t are correct as aux parameters with zkprm
	prm, err := zkprm.Public{Pedersen: partyI.Pedersen}.Prove(round.H.CloneWithID(round.SelfID), zkprm.Private{
		Lambda: round.lambda,
		Phi:    round.phi,
	})
	if err != nil {
		return nil, err
	}

	// Compute all ZKPoK Xⱼ = [xⱼ] G
	schXproto := make([]*pb.Scalar, round.S.Threshold)
	var schX *curve.Scalar
	for j := range schXproto {
		x := round.poly.Coefficients()[j+1]
		X := round.thisParty.polyExp.Coefficients()[j+1]
		schX, err = zksch.Prove(round.H.CloneWithID(round.SelfID), partyI.A[j], X, round.schnorrRand[j], x)
		if err != nil {
			return nil, errors.New("failed to generate schnorr")
		}
		schXproto[j] = pb.NewScalar(schX)
	}

	// create messages with encrypted shares
	msgs := make([]*pb.Message, 0, round.S.N()-1)
	for _, idJ := range round.S.Parties {
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
	return pb.MessageType_TypeRefreshThreshold4
}
