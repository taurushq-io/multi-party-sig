package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round1 struct {
	*roundBase

	decommitment []byte // uᵢ
}

func (round *round1) ProcessMessage(msg *pb.Message) error {
	// In the first round, no messages are expected.
	return nil
}

func (round *round1) GenerateMessages() ([]*pb.Message, error) {
	var err error

	round.thisParty.X = curve.NewIdentityPoint().ScalarBaseMult(round.p.PrivateECDSA)
	round.thisParty.A = curve.NewIdentityPoint().ScalarBaseMult(round.p.a)

	round.thisParty.rid = round.p.rid

	// commit to data in message 2
	round.thisParty.commitment, round.decommitment, err = round.h.Commit(round.selfID, round.thisParty.rid, round.thisParty.X, round.thisParty.A)
	if err != nil {
		return nil, err
	}

	return []*pb.Message{{
		Type:      pb.MessageType_TypeKeygen1,
		From:      round.selfID,
		Broadcast: pb.Broadcast_Reliable,
		Content: &pb.Message_Keygen1{
			Keygen1: &pb.Keygen1{
				Hash: round.thisParty.commitment,
			},
		},
	}}, nil
}

func (round *round1) Finalize() (round.Round, error) {
	return &round2{round}, nil
}

func (round *round1) MessageType() pb.MessageType {
	return pb.MessageType_TypeInvalid
}

func (round *round1) RequiredMessageCount() int {
	return 0
}

func (round *round1) IsProcessed(id party.ID) bool {
	if _, ok := round.parties[id]; !ok {
		return false
	}
	return true
}
