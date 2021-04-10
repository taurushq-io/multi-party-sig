package refresh

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	zkmod "github.com/taurusgroup/cmp-ecdsa/pkg/refresh/mod"
	zkprm "github.com/taurusgroup/cmp-ecdsa/pkg/refresh/prm"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

type output struct {
	*round3
	X *curve.Point // X = ∏ⱼ Xⱼ
}

func (round *output) ProcessMessage(msg *message.Message) error {
	j := msg.From()
	partyJ := round.parties[j]

	if err := partyJ.StoreMessage(msg); err != nil {
		return err
	}

	if !partyJ.Mod.Verify(round.session.HashForID(j), zkmod.Public{N: partyJ.N}) {
		return errors.New("mod failed")
	}
	if !partyJ.Prm.Verify(round.session.HashForID(j), zkprm.Public{
		N: partyJ.N,
		S: partyJ.S,
		T: partyJ.T,
	}) {
		return errors.New("prm failed")
	}

	if !zksch.Verify(round.session.HashForID(j), partyJ.B, partyJ.Y, partyJ.SchY) {
		return errors.New("schnorr Y failed")
	}

	i := round.session.SelfID()
	if !zksch.Verify(round.session.HashForID(j), partyJ.A[i], partyJ.X[i], partyJ.SchX) {
		return errors.New("schnorr X failed")
	}

	return nil
}

func (round *output) GenerateMessages() ([]*message.Message, error) {
	updatedShare := curve.NewScalar().Set(round.x)
	for j, partyJ := range round.parties {
		if j == round.session.SelfID() {
			updatedShare.Add(updatedShare, round.sentShares[round.session.SelfID()])
			continue
		}
		xDec := round.paillierSecret.Dec(partyJ.C)
		xScalar := curve.NewScalar().SetBigInt(xDec)
		updatedShare.Add(updatedShare, xScalar)
	}

	return nil, nil
}
