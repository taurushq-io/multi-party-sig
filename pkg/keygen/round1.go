package keygen

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

type round1 struct {
	session *session.Session

	thisParty *Party
	parties   map[uint32]*Party

	x   *curve.Scalar // x = xᵢ <- 𝔽ₚ
	rid []byte        // rid = ⊕ᵢ ridᵢ
	a   *curve.Scalar // a = aᵢ <- 𝔽ₚ
}

func (round *round1) ProcessMessage(msg message.Message) error {
	// In the first round, no messages are expected.
	return nil
}

func (round *round1) GenerateMessages() ([]message.Message, error) {

	round.x = curve.NewScalarRandom()
	round.a = curve.NewScalarRandom()

	msg2 := message2{
		X: curve.NewIdentityPoint().ScalarBaseMult(round.x),
		A: curve.NewIdentityPoint().ScalarBaseMult(round.a),
	}
	// Sample rid, u
	var err error
	msg2.RID, err = round.session.RandomSlice()
	if err != nil {
		return nil, err
	}
	msg2.U, err = round.session.RandomSlice()
	if err != nil {
		return nil, err
	}

	// Make hash of msg2
	h := round.session.HashForSelf()
	V, err := h.Sum(msg2.RID, msg2.X.Bytes(), msg2.A.Bytes(), msg2.U)
	if err != nil {
		return nil, err
	}
	msg1 := message1{V}

	round.thisParty.message1 = msg1
	round.thisParty.message2 = msg2

	fmt.Println(msg1)
	// broadcast the message
	return nil, nil
}

//func (round *round1) NextRound() state.Round {
//	return &round2{round}
//}
