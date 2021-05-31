package keygen_threshold

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zkmod "github.com/taurusgroup/cmp-ecdsa/pkg/zk/mod"
	zkprm "github.com/taurusgroup/cmp-ecdsa/pkg/zk/prm"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

type output struct {
	*round4
}

func (round *output) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFromID()
	partyJ := round.parties[j]

	body := msg.GetRefreshT4()

	// verify Schnorr proofs
	if len(body.SchF) != round.S.Threshold {
		return errors.New("wrong number of Schnorr commmitments")
	}
	for l := range body.SchF {
		schX := body.SchF[l].Unmarshal()
		X := partyJ.polyExp.Coefficients()[l+1]
		if !zksch.Verify(round.H.CloneWithID(j), partyJ.A[l], X, schX) {
			return errors.New("schnorr X failed")
		}
	}

	// decrypt share
	xJdec := round.S.Secret.Paillier.Dec(body.GetC().Unmarshal())
	xJ := curve.NewScalarBigInt(xJdec)
	if xJdec.Cmp(xJ.BigInt()) != 0 {
		return errors.New("share overflows")
	}

	// verify share with VSS
	index := curve.NewScalar().SetBytes([]byte(partyJ.ID))
	vss := partyJ.polyExp.Evaluate(index) // Fⱼ(idJ)
	X := curve.NewIdentityPoint().ScalarBaseMult(xJ)
	if !X.Equal(vss) {
		return errors.New("decrypted share is bad")
	}
	partyJ.shareReceived = xJ

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
	// add all shares to our secret
	for _, partyJ := range round.parties {
		round.S.Secret.ECDSA.Add(round.S.Secret.ECDSA, partyJ.shareReceived)
	}

	// [F₁(X), ..., Fₙ(X)]
	allPolyExps := make([]*polynomial.Exponent, round.S.N())
	// sum all public shares
	for i, partyIDJ := range round.S.Parties {
		partyJ := round.parties[partyIDJ]
		allPolyExps[i] = partyJ.polyExp
	}
	// summedPoly = ∑Fⱼ(X)
	summedPoly, err := polynomial.Sum(allPolyExps)
	if err != nil {
		return nil, err
	}

	updatedPublic := make([]*curve.Point, round.S.N())
	for i, id := range round.S.Parties {
		index := curve.NewScalar().SetBytes([]byte(id))
		updatedPublic[i] = summedPoly.Evaluate(index)
	}

	// update new public key
	for idxJ, j := range round.S.Parties {
		round.parties[j].ECDSA.Add(round.parties[j].ECDSA, updatedPublic[idxJ])
	}

	return nil, nil
}

func (round *output) Finalize() (round.Round, error) {
	return nil, nil
}

func (round *output) MessageType() pb.MessageType {
	return pb.MessageType_TypeRefresh3
}
