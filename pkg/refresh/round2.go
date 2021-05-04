package refresh

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
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

	partyJ.commitment = msg.GetRefresh1().GetHash()

	return partyJ.AddMessage(msg)
}

func (round *round2) GenerateMessages() ([]*pb.Message, error) {
	// Broadcast the message we created in round1
	return []*pb.Message{{
		Type:      pb.MessageType_TypeRefresh2,
		From:      round.selfID,
		Broadcast: pb.Broadcast_Basic,
		Content: &pb.Message_Refresh2{
			Refresh2: &pb.Refresh2{
				X:   pb.NewPointSlice(round.thisParty.X),
				A:   pb.NewPointSlice(round.thisParty.ASch),
				Y:   pb.NewPoint(round.thisParty.Y),
				B:   pb.NewPoint(round.thisParty.BSch),
				N:   pb.NewInt(round.thisParty.Pedersen.N),
				S:   pb.NewInt(round.thisParty.Pedersen.S),
				T:   pb.NewInt(round.thisParty.Pedersen.T),
				Rho: round.thisParty.rho,
				U:   round.decommitment,
			},
		},
	}}, nil
}

func (round *round2) Finalize() (round.Round, error) {
	return &round3{
		round2: round,
	}, nil
}

func (round *round2) MessageType() pb.MessageType {
	return pb.MessageType_TypeRefresh1
}

func (round *round2) RequiredMessageCount() int {
	return round.s.N() - 1
}

func (round *round2) IsProcessed(id party.ID) bool {
	panic("")
	return true
}

//func (round *round1) NextRound() state.Round {
//	return &round2{round}
//}
