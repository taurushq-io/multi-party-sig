package sign

import (
	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type abort1 struct {
	*round4
}

func (round *abort1) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFromID()
	partyJ := round.parties[j]

	return partyJ.AddMessage(msg)
}

func (round *abort1) GenerateMessages() ([]*pb.Message, error) {

	messages := make([]*pb.Message, 0, round.S.N()-1)

	return messages, nil
}

func (round *abort1) Finalize() (round.Round, error) {
	return &output{
		//abort1: round,
	}, nil
}

func (round *abort1) MessageType() pb.MessageType {
	return pb.MessageType_TypeSign3
}
