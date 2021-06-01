package refresh

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zkmod2 "github.com/taurusgroup/cmp-ecdsa/pkg/zk/mod"
	zkprm2 "github.com/taurusgroup/cmp-ecdsa/pkg/zk/prm"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

type output struct {
	*round3
}

func (round *output) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFromID()
	partyJ := round.parties[j]

	body := msg.GetRefresh3()

	// verify schnorr Y
	if !zksch.Verify(round.H.CloneWithID(j), partyJ.BSch, partyJ.Y, body.GetSchY().Unmarshal()) {
		return errors.New("schnorr Y failed")
	}

	// verify all Schnorr X
	for k := range round.S.PartyIDs() {
		schX := body.GetSchX()[k].Unmarshal()
		if !zksch.Verify(round.H.CloneWithID(j), partyJ.ASch[k], partyJ.X[k], schX) {
			return errors.New("schnorr X failed")
		}
	}

	// get idx of j
	idxJ := round.S.PartyIDs().GetIndex(j)

	// decrypt share
	xJdec := round.Secret.Paillier.Dec(body.GetC().Unmarshal())
	xJ := curve.NewScalarBigInt(xJdec)
	if xJdec.Cmp(xJ.BigInt()) != 0 {
		return errors.New("share overflows")
	}

	// verify share
	X := curve.NewIdentityPoint().ScalarBaseMult(xJ)
	if !X.Equal(partyJ.X[round.SelfIndex]) {
		return errors.New("decrypted share is bad")
	}
	round.xReceived[idxJ] = xJ

	// verify zkmod
	modPublic := zkmod2.Public{N: partyJ.Pedersen.N}
	if !modPublic.Verify(round.H.CloneWithID(j), body.GetMod()) {
		return errors.New("mod failed")
	}

	// verify zkprm
	prmPublic := zkprm2.Public{Pedersen: partyJ.Pedersen}
	if !prmPublic.Verify(round.H.CloneWithID(j), body.GetPrm()) {
		return errors.New("prm failed")
	}

	return partyJ.AddMessage(msg)
}

func (round *output) GenerateMessages() ([]*pb.Message, error) {
	// add all shares to our secret
	for _, xJ := range round.xReceived {
		round.Secret.ECDSA.Add(round.Secret.ECDSA, xJ)
	}

	updatedPublic := make([]curve.Point, round.S.N())

	// sum all public shares
	for _, partyJ := range round.parties {
		for idxK, Xk := range partyJ.X {
			updatedPublic[idxK].Add(&updatedPublic[idxK], Xk)
		}
	}

	// update new public key
	for idxJ, j := range round.S.PartyIDs() {
		round.parties[j].ECDSA.Add(round.parties[j].ECDSA, &updatedPublic[idxJ])
	}

	return nil, nil
}

func (round *output) Finalize() (round.Round, error) {
	return nil, nil
}

func (round *output) MessageType() pb.MessageType {
	return pb.MessageType_TypeRefresh3
}
