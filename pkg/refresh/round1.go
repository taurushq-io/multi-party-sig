package refresh

import (
	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round1 struct {
	*round.BaseRound

	p *Parameters

	thisParty *localParty
	parties   map[party.ID]*localParty

	// xReceived are the decrypted shares received from each party
	xReceived []*curve.Scalar

	// decommitment of the 2nd message
	decommitment hash.Decommitment // uᵢ
}

func (round *round1) ProcessMessage(*pb.Message) error {
	// In the first round, no messages are expected.
	return nil
}

func (round *round1) GenerateMessages() ([]*pb.Message, error) {
	var err error

	// generate elGamal + schnorr commitments
	round.thisParty.Y = curve.NewIdentityPoint().ScalarBaseMult(round.p.y)
	round.thisParty.BSch = curve.NewIdentityPoint().ScalarBaseMult(round.p.bSchnorr)

	// generate shares
	round.thisParty.X = make([]*curve.Point, round.S.N())
	round.thisParty.ASch = make([]*curve.Point, round.S.N())
	for idxJ := range round.S.Parties() {
		round.thisParty.X[idxJ] = curve.NewIdentityPoint().ScalarBaseMult(round.p.xSent[idxJ])
		round.thisParty.ASch[idxJ] = curve.NewIdentityPoint().ScalarBaseMult(round.p.aSchnorr[idxJ])
	}

	round.thisParty.Pedersen = round.p.ped
	round.thisParty.PaillierPublic = round.p.paillierSecret.PublicKey()

	// save our own share
	round.xReceived = make([]*curve.Scalar, round.S.N())
	round.xReceived[round.SelfIndex] = round.p.xSent[round.SelfIndex]

	// Sample ρ
	round.thisParty.rho = round.p.rho

	// commit to data in message 2
	round.thisParty.commitment, round.decommitment, err = round.H.Commit(round.SelfID,
		round.thisParty.X, round.thisParty.ASch, round.thisParty.Y, round.thisParty.BSch, round.thisParty.Pedersen, round.thisParty.rho)
	if err != nil {
		return nil, err
	}

	return []*pb.Message{{
		Type:      pb.MessageType_TypeRefresh1,
		From:      round.SelfID,
		Broadcast: pb.Broadcast_Reliable,
		Content: &pb.Message_Refresh1{
			Refresh1: &pb.Refresh1{
				Hash: round.thisParty.commitment,
			},
		},
	}}, nil
}

func (round *round1) Finalize() (round.Round, error) {
	return &round2{round}, nil
}

func (round *round1) MessageType() pb.MessageType {
	return pb.MessageType_TypeKeygen2
}

func (round *round1) RequiredMessageCount() int {
	return round.S.N()
}
func (round *round1) IsProcessed(id party.ID) bool {
	return true
}
