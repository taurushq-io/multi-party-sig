package keygen

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

type output struct {
	*round3
	X *curve.Point // X = ∑ⱼ Xⱼ
}

func (round *output) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFrom()
	partyJ, ok := round.parties[j]
	if !ok {
		return errors.New("sender not registered")
	}
	body := msg.GetKeygen3()

	if !zksch.Verify(round.h.CloneWithID(j), partyJ.A, partyJ.X, body.GetSchX().Unmarshal()) {
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

func (round *output) RequiredMessageCount() int {
	return round.s.N() - 1
}

func (round *output) IsProcessed(id party.ID) bool {
	return round.parties[id].keygen3 != nil
}
