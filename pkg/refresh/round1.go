package refresh

import (
	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round1 struct {
	*base

	// xReceived are the decrypted shares received from each party
	xReceived []*curve.Scalar

	// decommitment of the 2nd message
	decommitment []byte // uᵢ
}

func (round *round1) ProcessMessage(msg message.Message) error {
	// In the first round, no messages are expected.
	return nil
}

func (round *round1) GenerateMessages() ([]message.Message, error) {
	var err error

	// generate elGamal + schnorr commitments
	round.thisParty.Y = curve.NewIdentityPoint().ScalarBaseMult(round.p.y)
	round.thisParty.BSch = curve.NewIdentityPoint().ScalarBaseMult(round.p.bSchnorr)

	// generate shares
	round.thisParty.X = make([]*curve.Point, round.c.N())
	round.thisParty.ASch = make([]*curve.Point, round.c.N())
	for idxJ := range round.c.Parties() {
		round.thisParty.X[idxJ] = curve.NewIdentityPoint().ScalarBaseMult(round.p.xSent[idxJ])
		round.thisParty.ASch[idxJ] = curve.NewIdentityPoint().ScalarBaseMult(round.p.aSchnorr[idxJ])
	}

	round.thisParty.Pedersen = round.p.ped
	round.thisParty.PaillierPublic = round.p.paillierSecret.PublicKey()

	// save our own share
	round.xReceived = make([]*curve.Scalar, round.c.N())
	round.xReceived[round.c.SelfIndex()] = round.p.xSent[round.c.SelfIndex()]

	// Sample ρ
	round.thisParty.rho = round.p.rho

	// commit to data in message 2
	round.thisParty.commitment, round.decommitment, err = round.session.Commit(round.c.SelfID(),
		round.thisParty.X, round.thisParty.ASch, round.thisParty.Y, round.thisParty.BSch, round.thisParty.Pedersen, round.thisParty.rho)
	if err != nil {
		return nil, err
	}

	return []message.Message{&pb.Message{
		Type: pb.MessageType_Refresh1,
		From: round.c.SelfID(),
		To:   0,
		Content: &pb.Message_Refresh1{
			Refresh1: &pb.RefreshMessage1{
				Hash: round.thisParty.commitment,
			},
		},
	}}, nil
}

func (round *round1) Finalize() (round.Round, error) {
	return &round2{round}, nil
}

func (round *round1) MessageType() pb.MessageType {
	return pb.MessageType_Keygen2
}

func (round *round1) RequiredMessageCount() int {
	return round.c.N()
}
func (round *round1) IsProcessed(id uint32) bool {
	if _, ok := round.parties[id]; !ok {
		return false
	}
	return round.parties[id].Messages[round.MessageType()] == nil
}
