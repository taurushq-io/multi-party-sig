package keygen

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

type output struct {
	*round3
	X *curve.Point // X = ∑ⱼ Xⱼ
}

func (round *output) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFrom()
	partyJ := round.parties[j]

	body := msg.GetKeygen3()

	if !zksch.Verify(round.H.CloneWithID(j), partyJ.A, partyJ.X, body.GetSchX().Unmarshal()) {
		return errors.New("schnorr verification failed")
	}

	partyJ.keygen3 = body
	return nil
}

func (round *output) GenerateMessages() ([]*pb.Message, error) {
	round.X = curve.NewIdentityPoint()
	for _, partyJ := range round.parties {
		round.X.Add(round.X, partyJ.X)
	}
	return nil, nil
}

func (round *output) Finalize() (round.Round, error) {
	return nil, nil
}

func (round *output) MessageType() pb.MessageType {
	return pb.MessageType_TypeKeygen3
}
