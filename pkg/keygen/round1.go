package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/messages"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/state"
)

type msg1 struct {
	V []byte
}

type round1 struct {
	msgs map[party.ID]*msg1
	*round0
}

func (round *round1) ProcessMessage(msg *messages.Message) *state.Error {
	return nil
}

func (round *round1) GenerateMessages() ([]*messages.Message, *state.Error) {
	return nil, nil
}

//func (round *round0) NextRound() state.Round {
//	return &round1{round}
//}
