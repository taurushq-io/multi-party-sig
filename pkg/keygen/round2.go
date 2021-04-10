package keygen

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
)

type round2 struct {
	*round1
}

func (round *round2) ProcessMessage(msg *message.Message) error {
	// TODO unmarshal V and store
	return nil
}

func (round *round2) GenerateMessages() ([]*message.Message, error) {
	// Broadcast the message we created in round1
	fmt.Println(round.thisParty.message2)
	return nil, nil
}

//func (round *round1) NextRound() state.Round {
//	return &round2{round}
//}
