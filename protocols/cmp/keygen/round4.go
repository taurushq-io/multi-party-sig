package keygen

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
	zkmod "github.com/taurusgroup/cmp-ecdsa/pkg/zk/mod"
	zkprm "github.com/taurusgroup/cmp-ecdsa/pkg/zk/prm"
)

type round4 struct {
	*round3
	rid RID
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
func (r *round4) ProcessMessage(from party.ID, content message.Content) error {
	body := content.(*Keygen4)
	partyJ := r.Parties[from]

	// Save all X, VSSCommitments
	polyExp := body.VSSPolynomial
	// check that the constant coefficient is 0
	// if refresh then the polynomial is constant
	if !(r.VSSSecret.Constant().IsZero() == polyExp.IsConstant) {
		return ErrRound4VSSConstant
	}
	// check deg(Fⱼ) = t
	if polyExp.Degree() != r.SID.threshold {
		return ErrRound4VSSDegree
	}

	// Set Paillier
	Nj := body.Pedersen.N
	paillierPublicKey := paillier.NewPublicKey(Nj)
	if err := paillierPublicKey.Validate(); err != nil {
		return err
	}

	// Verify Pedersen
	if err := body.Pedersen.Validate(); err != nil {
		return err
	}

	// Verify decommit
	var rid RID
	rid.FromBytes(body.RID)

	if !r.HashForID(from).Decommit(partyJ.Commitment, body.Decommitment,
		rid, polyExp, body.SchnorrCommitments, body.Pedersen) {
		return ErrRound4Decommit
	}

	partyJ.RID = rid
	partyJ.Pedersen = body.Pedersen
	partyJ.Paillier = paillierPublicKey
	partyJ.VSSPolynomial = polyExp
	partyJ.SchnorrCommitments = body.SchnorrCommitments
	return nil
}

// GenerateMessages implements round.Round
//
// - set ρ = ⊕ⱼ ρⱼ and update hash state
// - prove Nᵢ is Blum
// - prove Pedersen parameters
// - prove Schnorr for all coefficients of fᵢ(X)
//   - if refresh skip constant coefficient
//
// - send proofs and encryption of share for Pⱼ
func (r *round4) GenerateMessages(out chan<- *message.Message) error {
	// RID = ⊕ⱼ RIDⱼ
	var rid RID
	for _, partyJ := range r.Parties {
		for i := 0; i < params.SecBytes; i++ {
			rid[i] ^= partyJ.RID[i]
		}
	}

	h := r.Hash()
	_, _ = h.WriteAny(rid, r.Self.ID)

	// Prove N is a blum prime with zkmod
	mod := zkmod.NewProof(h.Clone(), zkmod.Public{N: r.Self.Pedersen.N}, zkmod.Private{
		P:   r.Secret.Paillier.P(),
		Q:   r.Secret.Paillier.Q(),
		Phi: r.Secret.Paillier.Phi(),
	})

	// prove s, t are correct as aux parameters with zkprm
	prm := zkprm.NewProof(h.Clone(), zkprm.Public{Pedersen: r.Self.Pedersen}, zkprm.Private{
		Lambda: r.PedersenSecret,
		Phi:    r.Secret.Paillier.Phi(),
	})

	// create messages with encrypted shares
	for idJ, partyJ := range r.Parties {
		if idJ == r.Self.ID {
			continue
		}

		// compute fᵢ(idJ)
		index := idJ.Scalar()
		share := r.VSSSecret.Evaluate(index)
		// Encrypt share
		C, _ := partyJ.Paillier.Enc(share.BigInt())

		msg := r.MarshalMessage(&Keygen5{
			Mod:   mod,
			Prm:   prm,
			Share: C,
		}, idJ)
		if err := r.SendMessage(msg, out); err != nil {
			return err
		}
	}

	// Write Rho to the hash state
	r.rid = rid
	r.UpdateHashState(rid)

	return nil
}

// Next implements round.Round
func (r *round4) Next() round.Round {
	return &round5{
		round4: r,
	}
}

func (r *round4) MessageContent() message.Content {
	return &Keygen4{}
}

func (m *Keygen4) Validate() error {
	if m == nil {
		return errors.New("keygen.round3: message is nil")
	}
	if lRho := len(m.RID); lRho != params.SecBytes {
		return fmt.Errorf("keygen.round3: invalid Rho length (got %d, expected %d)", lRho, params.SecBytes)
	}

	if lU := len(m.Decommitment); lU != params.SecBytes {
		return fmt.Errorf("keygen.round3: invalid Decommitment length (got %d, expected %d)", lU, params.SecBytes)
	}

	if err := m.Pedersen.Validate(); err != nil {
		return fmt.Errorf("keygen.round3: %w", err)
	}

	if m.VSSPolynomial == nil {
		return errors.New("keygen.round3: VSSPolynomial is nil")
	}

	return nil
}

func (m *Keygen4) RoundNumber() types.RoundNumber {
	return 4
}
