package refresh_threshold

import (
	"errors"
	"fmt"

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
	if len(body.SchF) != round.S.Threshold+1 {
		return fmt.Errorf("refresh.output.ProcessMessage(): party %s: wrong number of Schnorr commitments", j)
	}
	for l := range body.SchF {
		// if in refresh, we know the constant coefficient is 0 so no need to check
		if !round.keygen && l == 0 {
			continue
		}
		schX := body.SchF[l].Unmarshal()
		X := partyJ.polyExp.Coefficients()[l+1]
		if !zksch.Verify(round.H.CloneWithID(j), partyJ.A[l], X, schX) {
			return fmt.Errorf("refresh.output.ProcessMessage(): party %s: failed to validate sch proof for coef %d", j, l)
		}
	}

	// decrypt share
	xJdec := round.S.Secret.Paillier.Dec(body.GetC().Unmarshal())
	xJ := curve.NewScalarBigInt(xJdec)
	if xJdec.Cmp(xJ.BigInt()) != 0 {
		return fmt.Errorf("refresh.output.ProcessMessage(): party %s: decrypted share is not in correct range", j)
	}

	// verify share with VSS
	index := curve.NewScalar().SetBytes([]byte(partyJ.ID))
	vss := partyJ.polyExp.Evaluate(index) // Fⱼ(idJ)
	X := curve.NewIdentityPoint().ScalarBaseMult(xJ)
	if !X.Equal(vss) {
		return fmt.Errorf("refresh.output.ProcessMessage(): party %s: failed to validate share from VSS", j)
	}
	partyJ.shareReceived = xJ

	// verify zkmod
	modPublic := zkmod.Public{N: partyJ.Pedersen.N}
	if !modPublic.Verify(round.H.CloneWithID(j), body.GetMod()) {
		return fmt.Errorf("refresh.output.ProcessMessage(): party %s: mod proof failed to verify", j)
	}

	// verify zkprm
	prmPublic := zkprm.Public{Pedersen: partyJ.Pedersen}
	if !prmPublic.Verify(round.H.CloneWithID(j), body.GetPrm()) {
		return fmt.Errorf("refresh.output.ProcessMessage(): party %s: prm proof failed to verify", j)
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
	for i, partyIDJ := range round.S.PartyIDs {
		partyJ := round.parties[partyIDJ]
		allPolyExps[i] = partyJ.polyExp
	}

	// summedPoly = ∑Fⱼ(X)
	summedPoly, err := polynomial.Sum(allPolyExps)
	if err != nil {
		return nil, fmt.Errorf("refresh.output.GenerateMessages(): sum polynomial exponent: %w", err)
	}

	updatedPublic := make([]*curve.Point, round.S.N())
	for i, id := range round.S.PartyIDs {
		index := curve.NewScalar().SetBytes([]byte(id))
		updatedPublic[i] = summedPoly.Evaluate(index)
	}

	// update new public key
	for idxJ, j := range round.S.PartyIDs {
		round.parties[j].ECDSA.Add(round.parties[j].ECDSA, updatedPublic[idxJ])
	}

	if err = round.S.RecomputeSSID(); err != nil {
		return nil, fmt.Errorf("refresh.output.GenerateMessages(): compute SSID: %w", err)
	}

	if err = round.S.Validate(); err != nil {
		return nil, fmt.Errorf("refresh.output.GenerateMessages(): validate new session: %w", err)
	}

	if !round.S.KeygenDone() {
		return nil, errors.New("refresh.output.GenerateMessages(): session is not in post keygen state")
	}

	return nil, nil
}

func (round *output) Finalize() (round.Round, error) {
	return nil, nil
}

func (round *output) MessageType() pb.MessageType {
	return pb.MessageType_TypeRefreshThreshold4
}
