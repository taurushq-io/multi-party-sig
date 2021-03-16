package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/messages"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/state"
)

func (round *round0) ProcessMessage(msg *messages.Message) *state.Error {
	return nil
}

func (round *round0) GenerateMessages() ([]*messages.Message, *state.Error) {
	round.selfParty.PaillierPublic, round.paillierSecret = paillier.KeyGen(256)

	return nil, nil
}

//func (round *round0) NextRound() state.Round {
//	return &round1{round}
//}
