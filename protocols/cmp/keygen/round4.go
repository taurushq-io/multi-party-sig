package keygen

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
	zkmod "github.com/taurusgroup/cmp-ecdsa/pkg/zk/mod"
	zkprm "github.com/taurusgroup/cmp-ecdsa/pkg/zk/prm"
)

var _ round.Round = (*round4)(nil)

type round4 struct {
	*round3
}

// ProcessMessage implements round.Round
//
// - store Fⱼ(X)
//   - if keygen, verify Fⱼ(0) != ∞
//   - if refresh, verify Fⱼ(0) == ∞
// - verify length of Schnorr commitments
// - validate Paillier
// - validate Pedersen
// - validate commitments
func (r *round4) ProcessMessage(j party.ID, content message.Content) error {
	body := content.(*Keygen4)

	// Save all X, VSSCommitments
	VSSPolynomial := body.VSSPolynomial
	// check that the constant coefficient is 0
	// if refresh then the polynomial is constant
	if !(r.VSSSecret.Constant().IsZero() == VSSPolynomial.IsConstant) {
		return ErrRound4VSSConstant
	}
	// check deg(Fⱼ) = t
	if VSSPolynomial.Degree() != r.Threshold {
		return ErrRound4VSSDegree
	}

	// Set Paillier
	Nj := body.Pedersen.N
	PaillierPublic := paillier.NewPublicKey(Nj)
	if err := PaillierPublic.Validate(); err != nil {
		return err
	}

	// Verify Pedersen
	if err := body.Pedersen.Validate(); err != nil {
		return err
	}

	// Verify decommit
	if !r.HashForID(j).Decommit(r.Commitments[j], body.Decommitment,
		body.RID, VSSPolynomial, body.SchnorrCommitments, body.Pedersen) {
		return ErrRound4Decommit
	}

	r.RIDs[j] = body.RID
	r.Pedersen[j] = body.Pedersen
	r.PaillierPublic[j] = PaillierPublic
	r.VSSPolynomials[j] = VSSPolynomial
	r.SchnorrCommitments[j] = body.SchnorrCommitments
	return nil
}

// Finalize implements round.Round
//
// - set rid = ⊕ⱼ ridⱼ and update hash state
// - prove Nᵢ is Blum
// - prove Pedersen parameters
// - prove Schnorr for all coefficients of fᵢ(X)
//   - if refresh skip constant coefficient
//
// - send proofs and encryption of share for Pⱼ
func (r *round4) Finalize(out chan<- *message.Message) (round.Round, error) {
	// RID = ⊕ⱼ RIDⱼ
	rid := newRID()
	for _, j := range r.PartyIDs() {
		rid.XOR(r.RIDs[j])
	}

	// temporary hash which does not modify the state
	h := r.Hash()
	_, _ = h.WriteAny(rid, r.SelfID())

	// Prove N is a blum prime with zkmod
	mod := zkmod.NewProof(h.Clone(), zkmod.Public{N: r.Pedersen[r.SelfID()].N}, zkmod.Private{
		P:   r.PaillierSecret.P(),
		Q:   r.PaillierSecret.Q(),
		Phi: r.PaillierSecret.Phi(),
	})

	// prove s, t are correct as aux parameters with zkprm
	prm := zkprm.NewProof(h.Clone(), zkprm.Public{Pedersen: r.Pedersen[r.SelfID()]}, zkprm.Private{
		Lambda: r.PedersenSecret,
		Phi:    r.PaillierSecret.Phi(),
	})

	// create messages with encrypted shares
	for _, j := range r.OtherPartyIDs() {
		// compute fᵢ(j)
		share := r.VSSSecret.Evaluate(j.Scalar())
		// Encrypt share
		C, _ := r.PaillierPublic[j].Enc(share.Int())

		msg := r.MarshalMessage(&Keygen5{
			Mod:   mod,
			Prm:   prm,
			Share: C,
		}, j)
		if err := r.SendMessage(msg, out); err != nil {
			return r, err
		}
	}

	// Write rid to the hash state
	r.UpdateHashState(rid)
	return &round5{
		round4: r,
		RID:    rid,
	}, nil
}

// MessageContent implements round.Round
func (r *round4) MessageContent() message.Content { return &Keygen4{} }

// Validate implements message.Content
func (m *Keygen4) Validate() error {
	if m == nil {
		return errors.New("keygen.round3: message is nil")
	}
	if err := m.RID.Validate(); err != nil {
		return fmt.Errorf("keygen.round3: %w", err)
	}

	if err := m.Decommitment.Validate(); err != nil {
		return fmt.Errorf("keygen.round3: %w", err)
	}

	if err := m.Pedersen.Validate(); err != nil {
		return fmt.Errorf("keygen.round3: %w", err)
	}

	if m.VSSPolynomial == nil {
		return errors.New("keygen.round3: VSSPolynomial is nil")
	}

	return nil
}

// RoundNumber implements message.Content
func (m *Keygen4) RoundNumber() types.RoundNumber { return 4 }
