package sign

import (
	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type abort2 struct {
	*output
}

func (round *abort2) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFromID()
	partyJ := round.parties[j]

	return partyJ.AddMessage(msg)
}

func (round *abort2) GenerateMessages() ([]*pb.Message, error) {

	messages := make([]*pb.Message, 0, round.S.N()-1)

	return messages, nil
}

func (round *abort2) Finalize() (round.Round, error) {
	return &output{
		//abort2: round,
	}, nil
}

func (round *abort2) MessageType() pb.MessageType {
	return pb.MessageType_TypeSign3
}
