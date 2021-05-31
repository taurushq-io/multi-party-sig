package keygen_threshold

import (
	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round2 struct {
	*round1
	hashOfHashes []byte
}

func (round *round2) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFromID()
	partyJ := round.parties[j]

	partyJ.commitment = msg.GetRefreshT1().GetHash()

	return partyJ.AddMessage(msg)
}

func (round *round2) GenerateMessages() ([]*pb.Message, error) {
	var err error
	// Broadcast the message we created in round1
	h := round.H.Clone()
	for _, partyID := range round.S.Parties {
		_, err = h.Write(round.parties[partyID].commitment)
		if err != nil {
			return nil, err
		}
	}
	round.hashOfHashes, err = h.ReadBytes(make([]byte, params.HashBytes))
	if err != nil {
		return nil, err
	}

	return []*pb.Message{{
		Type:      pb.MessageType_TypeRefreshThreshold2,
		From:      round.SelfID,
		Broadcast: pb.Broadcast_Basic,
		RefreshT2: &pb.RefreshT2{HashOfHashes: round.hashOfHashes},
	}}, nil
}

func (round *round2) Finalize() (round.Round, error) {
	return &round3{
		round2: round,
	}, nil
}

func (round *round2) MessageType() pb.MessageType {
	return pb.MessageType_TypeRefreshThreshold1
}
