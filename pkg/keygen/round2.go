package keygen

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round2 struct {
	*round1
}

func (round *round2) ProcessMessage(msg message.Message) error {
	m := msg.(*pb.Message)
	j := m.GetFrom()
	partyJ, ok := round.parties[j]
	if !ok {
		return errors.New("sender not registered")
	}

	partyJ.commitment = m.GetKeygen1().GetHash()

	return partyJ.AddMessage(msg)
}

func (round *round2) GenerateMessages() ([]message.Message, error) {
	// Broadcast the message we created in round1
	return []message.Message{&pb.Message{
		Type: pb.MessageType_Keygen2,
		From: round.c.SelfID(),
		To:   0,
		Content: &pb.Message_Keygen2{
			Keygen2: &pb.KeygenMessage2{
				Rid: round.thisParty.rid,
				X:   pb.NewPoint(round.thisParty.X),
				A:   pb.NewPoint(round.thisParty.A),
				U:   round.decommitment,
			},
		},
	}}, nil
}

func (round *round2) Finalize() (round.Round, error) {
	return &round3{round, make([]byte, params.SecBytes)}, nil
}

func (round *round2) MessageType() pb.MessageType {
	return pb.MessageType_Keygen1
}

func (round *round2) RequiredMessageCount() int {
	return round.c.N() - 1
}

func (round *round2) IsProcessed(id uint32) bool {
	//TODO
	return true
}

//func (round *round1) NextRound() state.Round {
//	return &round2{round}
//}
