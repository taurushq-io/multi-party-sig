package keygen

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

type round3 struct {
	*round2

	rid []byte // rid = ⊕ᵢ ridᵢ
}

func (round *round3) ProcessMessage(msg message.Message) error {
	var err error

	j := msg.GetFrom()
	partyJ, ok := round.parties[j]
	if !ok {
		return errors.New("sender not registered")
	}
	m := msg.(*pb.Message)
	body := m.GetKeygen2()

	rid := body.GetRid()
	if len(rid) != params.SecBytes {
		return errors.New("rid is wrong length")
	}
	partyJ.rid = rid

	if partyJ.X, err = body.GetX().Unmarshal(); err != nil {
		return err
	}
	if partyJ.A, err = body.GetA().Unmarshal(); err != nil {
		return err
	}

	decommitment := body.GetU()
	if !round.session.Decommit(j, partyJ.commitment, decommitment, partyJ.rid, partyJ.X, partyJ.A) {
		return errors.New("failed to decommit")
	}

	return partyJ.AddMessage(msg)
}

func (round *round3) GenerateMessages() ([]message.Message, error) {
	// rid = ⊕ⱼ ridⱼ
	round.rid = make([]byte, params.SecBytes)
	for _, partyJ := range round.parties {
		for i := 0; i < params.SecBytes; i++ {
			round.rid[i] ^= partyJ.rid[i]
		}
	}

	// include the agreed upon rid in the session
	if err := round.session.UpdateParams(round.rid); err != nil {
		return nil, err
	}

	// Schnorr proof
	partyI := round.thisParty
	proofX, err := zksch.Prove(round.session.HashForSelf(), partyI.A, partyI.X, round.p.a, round.p.PrivateECDSA)
	if err != nil {
		return nil, errors.New("failed to generate schnorr")
	}

	return []message.Message{&pb.Message{
		Type: pb.MessageType_Keygen3,
		From: round.c.SelfID(),
		To:   0,
		Content: &pb.Message_Keygen3{
			Keygen3: &pb.KeygenMessage3{
				SchX: pb.NewScalar(proofX),
			},
		},
	}}, nil
}

func (round *round3) Finalize() (round.Round, error) {
	return &output{
		round3: round,
		X:      curve.NewIdentityPoint(),
	}, nil
}

func (round *round3) MessageType() pb.MessageType {
	return pb.MessageType_Keygen2
}

func (round *round3) RequiredMessageCount() int {
	return round.c.N() - 1
}

func (round *round3) IsProcessed(id uint32) bool {
	panic("")
	return true
}

//func (round *round1) NextRound() state.Round {
//	return &round2{round}
//}
