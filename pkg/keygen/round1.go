package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round1 struct {
	*roundBase

	decommitment []byte // uᵢ
}

func (round *round1) ProcessMessage(msg message.Message) error {
	// In the first round, no messages are expected.
	return nil
}

func (round *round1) GenerateMessages() ([]message.Message, error) {
	var err error

	round.thisParty.X = curve.NewIdentityPoint().ScalarBaseMult(round.p.PrivateECDSA)
	round.thisParty.A = curve.NewIdentityPoint().ScalarBaseMult(round.p.a)

	round.thisParty.rid = round.p.rid

	// commit to data in message 2
	round.thisParty.commitment, round.decommitment, err = round.session.Commit(round.c.SelfID(), round.thisParty.rid, round.thisParty.X, round.thisParty.A)
	if err != nil {
		return nil, err
	}

	return []message.Message{&pb.Message{
		Type: pb.MessageType_Keygen1,
		From: round.c.SelfID(),
		To:   0,
		Content: &pb.Message_Keygen1{
			Keygen1: &pb.KeygenMessage1{
				Hash: round.thisParty.commitment,
			},
		},
	}}, nil
}

func (round *round1) Finalize() (round.Round, error) {
	return &round2{round}, nil
}

func (round *round1) MessageType() pb.MessageType {
	return pb.MessageType_Invalid
}

func (round *round1) RequiredMessageCount() int {
	return 0
}

func (round *round1) IsProcessed(id uint32) bool {
	if _, ok := round.parties[id]; !ok {
		return false
	}
	return true
}
