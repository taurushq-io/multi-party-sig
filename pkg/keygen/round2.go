package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/messages"
	"github.com/taurusgroup/cmp-ecdsa/pkg/state"
)

type round2 struct {
	*round1
}

func (round *round2) ProcessMessage(msg *messages.Message) *state.Error {
	return nil
}

func (round *round2) GenerateMessages() ([]*messages.Message, *state.Error) {
	return nil, nil
}

//func (round *round0) NextRound() state.Round {
//	return &round1{round}
//}
