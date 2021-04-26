package keygen

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

type output struct {
	*round3
	X *curve.Point // X = ∑ⱼ Xⱼ
}

func (round *output) ProcessMessage(msg message.Message) error {
	j := msg.GetFrom()
	partyJ, ok := round.parties[j]
	if !ok {
		return errors.New("sender not registered")
	}
	m := msg.(*pb.Message)
	body := m.GetKeygen3()

	if !zksch.Verify(round.session.HashForID(j), partyJ.A, partyJ.X, body.GetSchX().Unmarshal()) {
		return errors.New("schnorr verification failed")
	}

	return partyJ.AddMessage(msg)
}

func (round *output) GenerateMessages() ([]message.Message, error) {
	round.X = curve.NewIdentityPoint()
	for _, party := range round.parties {
		round.X.Add(round.X, party.X)
	}
	return nil, nil
}

func (round *output) Finalize() (round.Round, error) {
	return nil, nil
}

func (round *output) MessageType() pb.MessageType {
	return pb.MessageType_Keygen3
}

func (round *output) RequiredMessageCount() int {
	return round.c.N() - 1
}

func (round *output) IsProcessed(id uint32) bool {
	panic("implement me")
}
