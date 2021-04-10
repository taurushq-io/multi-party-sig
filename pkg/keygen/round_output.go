package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/state"
)

type output struct {
	*round3
	X *curve.Point // X = ∑ⱼ Xⱼ
}

func (round *output) ProcessMessage(msg *message.Message) error {
	j := msg.From()
	A := round.parties[j].A
	X := round.parties[j].X
	z := round.parties[j].Z

	// We don't use the standard Zk stuff here, because the proof is interactive
	e, err := round.session.HashToScalar(j, round.rid, X.Bytes())
	if err != nil {
		return state.NewError(0, err)
	}

	// lhs = [z]•G (= [a+ex]•G)
	// rhs = [e]•X + A ([ex]•G + [a]G = [a+ex]•G)
	lhs := curve.NewIdentityPoint().ScalarBaseMult(z)
	rhs := curve.NewIdentityPoint().ScalarMult(e, X)
	rhs.Add(rhs, A)
	if lhs.Equal(rhs) != 1 {
		panic("")
	}
	return nil
}

func (round *output) GenerateMessages() ([]*message.Message, error) {
	round.X = curve.NewIdentityPoint()
	for _, party := range round.parties {
		round.X.Add(round.X, party.X)
	}
	return nil, nil
}
