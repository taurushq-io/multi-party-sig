package refresh

import (
	"bytes"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round3 struct {
	*round2
}

// ProcessMessage implements round.Round
//
// - verify H(ssid, V₁, ..., Vₙ) against received hash
func (round *round3) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFromID()
	partyJ := round.parties[j]

	if !bytes.Equal(msg.GetRefresh2().HashOfHashes, round.hashOfHashes) {
		return fmt.Errorf("refresh.round3.ProcessMessage(): party %s sent different hash than ours", j)
	}

	return partyJ.AddMessage(msg)
}

// GenerateMessages implements round.Round
//
// - send all committed data
func (round *round3) GenerateMessages() ([]*pb.Message, error) {
	// Broadcast the message we created in round1
	return []*pb.Message{{
		Type:      pb.MessageType_TypeRefresh3,
		From:      round.SelfID,
		Broadcast: pb.Broadcast_Basic,
		Refresh3: &pb.Refresh3{
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

// Finalize implements round.Round
func (round *round3) Finalize() (round.Round, error) {
	return &round4{
		round3: round,
	}, nil
}

func (round *round3) MessageType() pb.MessageType {
	return pb.MessageType_TypeRefresh2
}
