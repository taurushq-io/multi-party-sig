package keygen

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round2 struct {
	*round1
}

func (round *round2) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFrom()
	partyJ, ok := round.parties[j]
	if !ok {
		return errors.New("sender not registered")
	}

	partyJ.commitment = msg.GetKeygen1().GetHash()
	partyJ.keygen1 = msg.GetKeygen1()

	return nil
}

func (round *round2) GenerateMessages() ([]*pb.Message, error) {
	// Broadcast the message we created in round1
	return []*pb.Message{{
		Type:      pb.MessageType_TypeKeygen2,
		From:      round.selfID,
		Broadcast: pb.Broadcast_Basic,
		Content: &pb.Message_Keygen2{
			Keygen2: &pb.Keygen2{
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
	return pb.MessageType_TypeKeygen1
}

func (round *round2) RequiredMessageCount() int {
	return round.s.N() - 1
}

func (round *round2) IsProcessed(id party.ID) bool {
	return round.parties[id].keygen1 != nil
}
