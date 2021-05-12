package refresh

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	zkmod "github.com/taurusgroup/cmp-ecdsa/pkg/refresh/mod"
	zkprm "github.com/taurusgroup/cmp-ecdsa/pkg/refresh/prm"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

type output struct {
	*round3
	X *curve.Point // X = ∏ⱼ Xⱼ
	x *curve.Scalar
}

func (round *output) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFrom()
	partyJ, ok := round.parties[j]
	if !ok {
		return errors.New("sender not registered")
	}
	body := msg.GetRefresh3()

	// verify schnorr Y
	if !zksch.Verify(round.H.CloneWithID(j), partyJ.BSch, partyJ.Y, body.GetSchY().Unmarshal()) {
		return errors.New("schnorr Y failed")
	}

	// verify all Schnorr X
	for k := range round.S.Parties() {
		schX := body.GetSchX()[k].Unmarshal()
		if !zksch.Verify(round.H.CloneWithID(j), partyJ.ASch[k], partyJ.X[k], schX) {
			return errors.New("schnorr X failed")
		}
	}

	// get idx of j
	idxJ := round.S.Parties().GetIndex(j)

	// decrypt share
	xJdec := round.p.paillierSecret.Dec(body.GetC().Unmarshal())
	xJ := curve.NewScalarBigInt(xJdec)
	// TODO check if this is true
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
	modPublic := zkmod.Public{N: partyJ.Pedersen.N}
	if !modPublic.Verify(round.H.CloneWithID(j), body.GetMod()) {
		return errors.New("mod failed")
	}

	// verify zkprm
	prmPublic := zkprm.Public{Pedersen: partyJ.Pedersen}
	if !prmPublic.Verify(round.H.CloneWithID(j), body.GetPrm()) {
		return errors.New("prm failed")
	}

	return partyJ.AddMessage(msg)
}

func (round *output) GenerateMessages() ([]*pb.Message, error) {
	round.x = curve.NewScalar()
	for _, xJ := range round.xReceived {
		round.x.Add(round.x, xJ)
	}

	updatedPublic := make([]*curve.Point, round.S.N())
	// set old public key
	for idxJ, j := range round.S.Parties() {
		updatedPublic[idxJ] = curve.NewIdentityPoint().Set(round.parties[j].Public)
	}

	// sum all public shares
	for _, partyJ := range round.parties {
		for idxK, Xk := range partyJ.X {
			updatedPublic[idxK].Add(updatedPublic[idxK], Xk)
		}
	}

	//TODO for debug
	round.X = curve.NewIdentityPoint()
	// update new public key
	for idxJ, j := range round.S.Parties() {
		round.parties[j].PublicNew = updatedPublic[idxJ]
		round.X.Add(round.X, updatedPublic[idxJ])
	}

	return nil, nil
}

func (round *output) Finalize() (round.Round, error) {

	return nil, nil
}

func (round *output) MessageType() pb.MessageType {
	return pb.MessageType_TypeRefresh3
}

func (round *output) RequiredMessageCount() int {
	return 0
}

func (round *output) IsProcessed(id party.ID) bool {
	panic("implement me")
}
