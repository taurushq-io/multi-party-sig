package refresh_threshold

import (
	"bytes"
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round3 struct {
	*round2
}

func (round *round3) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFromID()
	partyJ := round.parties[j]

	if !bytes.Equal(msg.GetRefreshT2().HashOfHashes, round.hashOfHashes) {
		return errors.New("hashes are incompatible")
	}

	return partyJ.AddMessage(msg)
}

func (round *round3) GenerateMessages() ([]*pb.Message, error) {
	// Broadcast the message we created in round1
	return []*pb.Message{{
		Type:      pb.MessageType_TypeRefresh2,
		From:      round.SelfID,
		Broadcast: pb.Broadcast_Basic,
		RefreshT3: &pb.RefreshT3{
			Rho: round.thisParty.rho,
			F:   pb.NewPolynomialExponent(round.thisParty.polyExp),
			A:   pb.NewPointSlice(round.thisParty.A),
			N:   pb.NewInt(round.thisParty.Pedersen.N),
			S:   pb.NewInt(round.thisParty.Pedersen.S),
			T:   pb.NewInt(round.thisParty.Pedersen.T),
			U:   round.decommitment,
		},
	}}, nil
}

func (round *round3) Finalize() (round.Round, error) {
	return &round4{
		round3: round,
	}, nil
}

func (round *round3) MessageType() pb.MessageType {
	return pb.MessageType_TypeRefreshThreshold3
}
