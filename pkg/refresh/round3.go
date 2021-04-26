package refresh

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
	zkmod "github.com/taurusgroup/cmp-ecdsa/pkg/refresh/mod"
	zkprm "github.com/taurusgroup/cmp-ecdsa/pkg/refresh/prm"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

type round3 struct {
	*round2
	rho []byte
}

func (round *round3) ProcessMessage(msg message.Message) error {
	var err error

	j := msg.GetFrom()
	partyJ, ok := round.parties[j]
	if !ok {
		return errors.New("sender not registered")
	}
	m := msg.(*pb.Message)
	body := m.GetRefresh2()

	// Set rho
	rho := body.GetRho()
	if len(rho) != params.SecBytes {
		return errors.New("rho is wrong length")
	}
	partyJ.rho = rho

	// Save all X, A
	if partyJ.X, err = pb.UnmarshalPoints(body.GetX()); err != nil {
		return err
	}
	if partyJ.ASch, err = pb.UnmarshalPoints(body.GetA()); err != nil {
		return err
	}

	// Save Y, B
	if partyJ.Y, err = body.GetY().Unmarshal(); err != nil {
		return err
	}
	if partyJ.BSch, err = body.GetB().Unmarshal(); err != nil {
		return err
	}

	// Set Paillier
	Nj := body.GetN().Unmarshal()
	if Nj.BitLen() != params.PaillierBits {
		return errors.New("N is the wrong number of bits")
	}
	partyJ.PaillierPublic = paillier.NewPublicKey(Nj)

	// Set Pedersen
	partyJ.Pedersen = &pedersen.Parameters{
		N: Nj,
		S: body.GetS().Unmarshal(),
		T: body.GetT().Unmarshal(),
	}
	if !partyJ.Pedersen.IsValid() {
		return errors.New("pedersen invalid")
	}

	// Verify shares sum to 0
	sum := curve.NewIdentityPoint()
	for _, X := range partyJ.X {
		sum.Add(sum, X)
	}
	if !sum.IsIdentity() {
		return errors.New("sum of public keys is not 0")
	}

	// Verify decommit
	decommitment := body.GetU()
	if !round.session.Decommit(j, partyJ.commitment, decommitment,
		partyJ.X, partyJ.ASch, partyJ.Y, partyJ.BSch, partyJ.Pedersen, partyJ.rho) {
		return errors.New("failed to decommit")
	}

	return partyJ.AddMessage(msg)
}

func (round *round3) GenerateMessages() ([]message.Message, error) {
	// ρ = ⊕ⱼ ρⱼ
	round.rho = make([]byte, params.SecBytes)
	for _, partyJ := range round.parties {
		for i := 0; i < params.SecBytes; i++ {
			round.rho[i] ^= partyJ.rho[i]
		}
	}

	// Write rho to the hash state
	if err := round.session.UpdateParams(round.rho); err != nil {
		return nil, err
	}

	partyI := round.thisParty

	// Prove N is a blum prime with zkmod
	mod, err := zkmod.Public{N: partyI.Pedersen.N}.Prove(round.session.HashForSelf(), zkmod.Private{
		P:   round.p.p,
		Q:   round.p.q,
		Phi: round.p.phi,
	})
	if err != nil {
		return nil, err
	}

	// prove s, t are correct as aux parameters with zkprm
	prm, err := zkprm.Public{Pedersen: partyI.Pedersen}.Prove(round.session.HashForSelf(), zkprm.Private{
		Lambda: round.p.lambda,
		Phi:    round.p.phi,
	})
	if err != nil {
		return nil, err
	}

	// Compute ZKPoK for Y = gʸ
	schY, err := zksch.Prove(round.session.HashForSelf(), partyI.BSch, partyI.Y, round.p.bSchnorr, round.p.y)
	if err != nil {
		return nil, errors.New("failed to generate schnorr")
	}

	// Compute all ZKPoK Xⱼ = [xⱼ] G
	schXproto := make([]*pb.Scalar, round.c.N())
	var schX *curve.Scalar
	for j := range round.c.Parties() {
		schX, err = zksch.Prove(round.session.HashForSelf(), partyI.ASch[j], partyI.X[j], round.p.aSchnorr[j], round.p.xSent[j])
		if err != nil {
			return nil, errors.New("failed to generate schnorr")
		}
		schXproto[j] = pb.NewScalar(schX)
	}

	// create messages with encrypted shares
	msgs := make([]message.Message, 0, round.c.N()-1)
	for j, idJ := range round.c.Parties() {
		if idJ == round.c.SelfID() {
			continue
		}

		partyJ := round.parties[idJ]

		// Encrypt share
		C, _ := partyJ.PaillierPublic.Enc(round.p.xSent[j].BigInt(), nil)

		msgs = append(msgs, &pb.Message{
			Type: pb.MessageType_Keygen3,
			From: round.c.SelfID(),
			To:   idJ,
			Content: &pb.Message_Refresh3{
				Refresh3: &pb.RefreshMessage3{
					Mod:  mod,
					Prm:  prm,
					C:    pb.NewCiphertext(C),
					SchX: schXproto,
					SchY: pb.NewScalar(schY),
				},
			},
		})
	}

	return msgs, nil
}

func (round *round3) Finalize() (round.Round, error) {
	return &output{
		round3: round,
	}, nil
}

func (round *round3) MessageType() pb.MessageType {
	return pb.MessageType_Refresh2
}

func (round *round3) RequiredMessageCount() int {
	return round.c.N() - 1
}

func (round *round3) IsProcessed(id uint32) bool {
	panic("implement me")
}
