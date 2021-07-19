package keygen

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/internal/writer"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
	zkmod "github.com/taurusgroup/cmp-ecdsa/pkg/zk/mod"
	zkprm "github.com/taurusgroup/cmp-ecdsa/pkg/zk/prm"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

type round5 struct {
	*round4
	newSession *Session
	newSecret  *Secret
}

// ProcessMessage implements round.Round
//
// - decrypt share
// - verify VSS
func (r *round5) ProcessMessage(from party.ID, content message.Content) error {
	body := content.(*Keygen5)
	partyJ := r.Parties[from]
	// decrypt share
	xJdec, err := r.Secret.Paillier.Dec(body.Share)
	if err != nil {
		return err
	}
	xJ := curve.NewScalarBigInt(xJdec)
	if xJdec.Cmp(xJ.BigInt()) != 0 {
		return ErrRound5Decrypt
	}

	// verify share with VSS
	index := r.Self.ID.Scalar()
	vss := partyJ.VSSPolynomial.Evaluate(index) // Fⱼ(idJ)
	X := curve.NewIdentityPoint().ScalarBaseMult(xJ)
	if !X.Equal(vss) {
		return ErrRound5VSS
	}

	// verify zkmod
	if !body.Mod.Verify(r.HashForID(from), zkmod.Public{N: partyJ.Pedersen.N}) {
		return ErrRound5ZKMod
	}

	// verify zkprm
	if !body.Prm.Verify(r.HashForID(from), zkprm.Public{Pedersen: partyJ.Pedersen}) {
		return ErrRound5ZKPrm
	}

	partyJ.ShareReceived = xJ
	return nil
}

// GenerateMessages implements round.Round
//
// - sum of all received shares
// - compute group public key and individual public keys
// - recompute session SSID
// - validate Session
// - write new ssid hash to old hash state
// - create proof of knowledge of secret
func (r *round5) GenerateMessages(out chan<- *message.Message) error {
	// add all shares to our secret
	newSecret := r.Secret.Clone()
	for _, partyJ := range r.Parties {
		newSecret.ECDSA.Add(newSecret.ECDSA, partyJ.ShareReceived)
	}

	// [F₁(X), …, Fₙ(X)]
	allPolyExps := make([]*polynomial.Exponent, 0, len(r.Parties))
	for _, partyJ := range r.Parties {
		allPolyExps = append(allPolyExps, partyJ.VSSPolynomial)
	}

	// summedPoly = F(X) = ∑Fⱼ(X)
	summedPoly, err := polynomial.Sum(allPolyExps)
	if err != nil {
		return err
	}

	// compute the new public key share Xⱼ = F(j) (+X'ⱼ if doing a refresh)
	newPublic := make(map[party.ID]*Public, len(r.Parties))
	for idJ, partyJ := range r.Parties {
		newPublicJ := partyJ.Clone()
		newPublicShareECDSA := summedPoly.Evaluate(idJ.Scalar())
		newPublicJ.ECDSA.Add(newPublicJ.ECDSA, newPublicShareECDSA)
		newPublic[idJ] = newPublicJ
	}

	updatedSession, err := newSession(r.SID, newPublic, r.rid)
	if err != nil {
		return err
	}

	// write new ssid to hash, to bind the Schnorr proof to this new session
	// Write SSID, selfID to temporary hash
	h := r.Hash()
	_, _ = h.WriteAny(&writer.BytesWithDomain{
		TheDomain: "SSID",
		Bytes:     updatedSession.SSID(),
	}, r.Self.ID)

	proof := zksch.Prove(h,
		r.Self.SchnorrCommitments,
		newPublic[r.Self.ID].ECDSA,
		r.SchnorrRand,
		newSecret.ECDSA)

	// send to all
	msg := r.MarshalMessage(&KeygenOutput{Proof: proof}, r.OtherPartyIDs()...)
	if err = r.SendMessage(msg, out); err != nil {
		return err
	}

	r.UpdateHashState(&writer.BytesWithDomain{
		TheDomain: "SSID",
		Bytes:     updatedSession.SSID(),
	})
	r.newSession = updatedSession
	r.newSecret = newSecret

	return nil
}

// Next implements round.Round
func (r *round5) Next() round.Round {
	return &output{r}
}

func (r *round5) MessageContent() message.Content {
	return &Keygen5{}
}

func (m *Keygen5) Validate() error {
	if m == nil {
		return errors.New("keygen.round4: message is nil")
	}
	if m.Mod == nil {
		return errors.New("keygen.round4: zkmod proof is nil")
	}
	if m.Prm == nil {
		return errors.New("keygen.round4: zkprm proof is nil")
	}
	if m.Share == nil {
		return errors.New("keygen.round4: Share proof is nil")
	}
	return nil
}

func (m *Keygen5) RoundNumber() types.RoundNumber {
	return 5
}
