package keygen

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/internal/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol/types"
	zkmod "github.com/taurusgroup/cmp-ecdsa/pkg/zk/mod"
	zkprm "github.com/taurusgroup/cmp-ecdsa/pkg/zk/prm"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

var _ round.Round = (*round4)(nil)

type round4 struct {
	*round3

	// SchnorrCommitments[j] = Aⱼ
	// Commitment for proof of knowledge in the last round
	SchnorrCommitments map[party.ID]*zksch.Commitment // Aⱼ
}

// ProcessMessage implements round.Round.
//
// - store Fⱼ(X)
//   - if keygen, verify Fⱼ(0) != ∞
//   - if refresh, verify Fⱼ(0) == ∞
// - verify length of Schnorr commitments
// - validate Paillier
// - validate Pedersen
// - validate commitments.
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
	PaillierPublic, err := paillier.NewPublicKey(body.N)
	if err != nil {
		return err
	}

	// Verify Pedersen
	Pedersen, err := pedersen.New(body.N, body.S, body.T)
	if err != nil {
		return err
	}

	// Verify decommit
	if !r.HashForID(j).Decommit(r.Commitments[j], body.Decommitment,
		body.RID, body.C, VSSPolynomial, body.SchnorrCommitments, Pedersen) {
		return ErrRound4Decommit
	}

	r.RIDs[j] = body.RID
	r.ChainKeys[j] = body.RID
	r.N[j] = body.N
	r.S[j] = body.S
	r.T[j] = body.T
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
// - send proofs and encryption of share for Pⱼ.
func (r *round4) Finalize(out chan<- *message.Message) (round.Round, error) {
	// RID = ⊕ⱼ RIDⱼ
	// c = ⊕ⱼ cⱼ
	rid := newRID()
	chainKey := r.PreviousChainKey
	if chainKey == nil {
		chainKeyRID := newRID()
		for _, j := range r.PartyIDs() {
			rid.XOR(r.RIDs[j])
			chainKeyRID.XOR(r.ChainKeys[j])
		}
		chainKey = chainKeyRID
	}
	// temporary hash which does not modify the state
	h := r.Hash()
	_, _ = h.WriteAny(rid, r.SelfID())

	// Prove N is a blum prime with zkmod
	mod := zkmod.NewProof(h.Clone(), zkmod.Public{N: r.N[r.SelfID()]}, zkmod.Private{
		P:   r.PaillierSecret.P(),
		Q:   r.PaillierSecret.Q(),
		Phi: r.PaillierSecret.Phi(),
	})

	// prove s, t are correct as aux parameters with zkprm
	prm := zkprm.NewProof(h.Clone(), zkprm.Public{N: r.N[r.SelfID()], S: r.S[r.SelfID()], T: r.T[r.SelfID()]}, zkprm.Private{
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
		round4:   r,
		RID:      rid,
		ChainKey: chainKey,
	}, nil
}

// MessageContent implements round.Round.
func (r *round4) MessageContent() message.Content { return &Keygen4{} }

// Validate implements message.Content.
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

	if m.N == nil || m.S == nil || m.T == nil {
		return errors.New("keygen.round3: N,S,T invalid")
	}

	if m.VSSPolynomial == nil {
		return errors.New("keygen.round3: VSSPolynomial is nil")
	}

	return nil
}

// RoundNumber implements message.Content.
func (m *Keygen4) RoundNumber() types.RoundNumber { return 4 }
