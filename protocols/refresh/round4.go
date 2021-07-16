package refresh

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/internal/writer"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zkmod "github.com/taurusgroup/cmp-ecdsa/pkg/zk/mod"
	zkprm "github.com/taurusgroup/cmp-ecdsa/pkg/zk/prm"
)

type round4 struct {
	*round3
	rho []byte
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
func (r *round4) ProcessMessage(msg round.Message) error {
	j := msg.GetHeader().From
	partyJ := r.LocalParties[j]

	body := msg.(*Message).GetRefresh3()

	// verify Rho
	if len(body.Rho) != params.SecBytes {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: Rho is wrong lenght", j)
	}

	// Save all X, VSSCommitments
	polyExp := body.VSSPolynomial
	// check that the constant coefficient is 0
	// if refresh then the polynomial is constant
	if !(r.isRefresh() == polyExp.IsConstant) {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: exponent polynomial has non 0 constant", j)
	}
	// check deg(Fⱼ) = t
	if polyExp.Degree() != r.S.Threshold() {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: exponent polynomial has wrong degree", j)
	}

	// Set Paillier
	Nj := body.Pedersen.N
	paillierPublicKey := paillier.NewPublicKey(Nj)
	if err := paillierPublicKey.Validate(); err != nil {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: %w", j, err)
	}

	// Verify Pedersen
	if err := body.Pedersen.Validate(); err != nil {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: %w", j, err)
	}

	// Verify decommit
	if !r.Hash.Decommit(j, partyJ.Commitment, body.Decommitment,
		body.Rho, polyExp, body.SchnorrCommitments, body.Pedersen) {
		return fmt.Errorf("refresh.round4.ProcessMessage(): party %s: failed to decommit", j)
	}

	partyJ.Rho = body.Rho
	partyJ.Public.Pedersen = body.Pedersen
	partyJ.Public.Paillier = paillierPublicKey
	partyJ.VSSPolynomial = polyExp
	partyJ.SchnorrCommitments = body.SchnorrCommitments

	return nil // message is properly handled
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
func (r *round4) GenerateMessages() ([]round.Message, error) {
	// ρ = ⊕ⱼ ρⱼ
	r.rho = make([]byte, params.SecBytes)
	for _, partyJ := range r.LocalParties {
		for i := 0; i < params.SecBytes; i++ {
			r.rho[i] ^= partyJ.Rho[i]
		}
	}

	// Write Rho to the hash state
	_, _ = r.Hash.WriteAny(&writer.BytesWithDomain{
		TheDomain: "Rho",
		Bytes:     r.rho,
	})

	// Prove N is a blum prime with zkmod
	mod := zkmod.NewProof(r.Hash.CloneWithID(r.SelfID), zkmod.Public{N: r.Self.Public.Pedersen.N}, zkmod.Private{
		P:   r.PaillierSecret.P(),
		Q:   r.PaillierSecret.Q(),
		Phi: r.PaillierSecret.Phi(),
	})

	// prove s, t are correct as aux parameters with zkprm
	prm := zkprm.NewProof(r.Hash.CloneWithID(r.SelfID), zkprm.Public{Pedersen: r.Self.Public.Pedersen}, zkprm.Private{
		Lambda: r.PedersenSecret,
		Phi:    r.PaillierSecret.Phi(),
	})

	// create messages with encrypted shares
	msgs := make([]round.Message, 0, r.S.N()-1)
	for _, idJ := range r.S.PartyIDs() {
		if idJ == r.SelfID {
			continue
		}

		partyJ := r.LocalParties[idJ]

		// compute fᵢ(idJ)
		index := idJ.Scalar()
		share := r.VSSSecret.Evaluate(index)
		// Encrypt share
		C, _ := partyJ.Public.Paillier.Enc(share.BigInt())

		msgs = append(msgs, NewMessageRefresh4(r.SelfID, idJ, &Refresh4{
			Mod:   mod,
			Prm:   prm,
			Share: C,
		}))
	}

	return msgs, nil
}

// Finalize implements round.Round
func (r *round4) Finalize() (round.Round, error) {
	r.Next()
	return &round5{
		round4: r,
	}, nil
}

func (r *round4) ExpectedMessageID() round.MessageID {
	return MessageTypeRefresh3
}
