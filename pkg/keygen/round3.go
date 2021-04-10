package keygen

import (
	"bytes"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/state"
)

type round3 struct {
	*round2
}

func (round *round3) ProcessMessage(msg *message.Message) error {
	j := msg.From()
	msg1 := round.parties[j].message1
	msg2 := round.parties[j].message2
	computedV, err := round.session.Hash(j, msg2.RID, msg2.X.Bytes(), msg2.A.Bytes(), msg2.U)
	if err != nil {
		panic("")
	}

	if !bytes.Equal(msg1.V, computedV) {
		panic("")
	}

	if msg2.X.IsIdentity() {
		panic("")
	}
	return nil
}

func (round *round3) GenerateMessages() ([]*message.Message, error) {
	// rid = ⊕ⱼ ridⱼ
	ridLen := 64
	round.rid = make([]byte, ridLen)
	for _, partyJ := range round.parties {
		for i := 0; i < ridLen; i++ {
			round.rid[i] ^= partyJ.RID[i]
		}
	}

	// Schnorr proof

	// e = H(... rid, Xᵢ)
	e, err := round.session.HashToScalar(round.session.SelfID(), round.rid, round.thisParty.X.Bytes())
	if err != nil {
		return nil, state.NewError(0, err)
	}

	// z = a + ex mod q
	z := curve.NewScalar().MultiplyAdd(round.x, e, round.a)

	selfMessage3 := message3{z}
	round.thisParty.message3 = selfMessage3
	fmt.Println(selfMessage3)

	return nil, nil
}

//func (round *round1) NextRound() state.Round {
//	return &round2{round}
//}
