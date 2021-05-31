package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round2 struct {
	*round1
}

func (round *round2) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFromID()
	partyJ := round.parties[j]

	partyJ.commitment = msg.GetKeygen1().GetHash()
	partyJ.keygen1 = msg.GetKeygen1()

	return nil
}

func (round *round2) GenerateMessages() ([]*pb.Message, error) {
	// Broadcast the message we created in round1
	return []*pb.Message{{
		Type:      pb.MessageType_TypeKeygen2,
		From:      round.SelfID,
		Broadcast: pb.Broadcast_Basic,
		Keygen2: &pb.Keygen2{
			Rid: round.thisParty.rid,
			X:   pb.NewPoint(round.thisParty.X),
			A:   pb.NewPoint(round.thisParty.A),
			U:   round.decommitment,
		},
	}}, nil
}

func (round *round2) Finalize() (round.Round, error) {
	return &round3{round, make([]byte, params.SecBytes)}, nil
}

func (round *round2) MessageType() pb.MessageType {
	return pb.MessageType_TypeKeygen1
}
