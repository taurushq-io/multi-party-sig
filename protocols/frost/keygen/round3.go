package keygen

import (
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// This round corresponds with steps 2-4 of Round 2, Figure 1 in the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
type round3 struct {
	*round2

	// shareFrom is the secret share sent to us by a given party, including ourselves.
	//
	// shareFrom[l] corresponds to fₗ(i) in the Frost paper, with i our own ID.
	shareFrom map[party.ID]curve.Scalar
}

type message3 struct {
	// F_li is the secret share sent from party l to this party.
	F_li curve.Scalar
	// C_l is contribution to the chaining key for this party.
	C_l types.RID
	// Decommitment = uᵢ decommitment bytes
	Decommitment hash.Decommitment
}

// VerifyMessage implements round.Round.
func (r *round3) VerifyMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*message3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// check nil
	if body.F_li == nil {
		return round.ErrNilFields
	}

	if err := body.C_l.Validate(); err != nil {
		return err
	}

	// Verify that the commitment to the chain key contribution matches, and then xor
	// it into the accumulated chain key so far.
	if !r.HashForID(from).Decommit(r.ChainKeyCommitments[from], body.Decommitment, body.C_l) {
		return fmt.Errorf("failed to verify chain key commitment")
	}
	return nil
}

// StoreMessage implements round.Round.
//
// Verify the VSS condition here since we will not be sending this message to other parties for verification.
func (r *round3) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*message3)

	// These steps come from Figure 1, Round 2 of the Frost paper

	// 2. "Each Pᵢ verifies their shares by calculating
	//
	//   fₗ(i) * G =? ∑ₖ₌₀ᵗ (iᵏ mod q) * ϕₗₖ
	//
	// aborting if the check fails."
	expected := body.F_li.ActOnBase()
	actual := r.Phi[from].Evaluate(r.SelfID().Scalar(r.Group()))
	if !expected.Equal(actual) {
		return fmt.Errorf("VSS failed to validate")
	}

	r.shareFrom[from] = body.F_li
	r.ChainKeys[from] = body.C_l

	return nil
}

// Finalize implements round.Round.
func (r *round3) Finalize(chan<- *round.Message) (round.Round, error) {
	ChainKey := types.EmptyRID()
	for _, j := range r.PartyIDs() {
		ChainKey.XOR(r.ChainKeys[j])
	}

	// These steps come from Figure 1, Round 2 of the Frost paper

	// 3. "Each P_i calculates their long-lived private signing share by computing
	// sᵢ = ∑ₗ₌₁ⁿ fₗ(i), stores s_i securely, and deletes each fₗ(i)"

	s_i := r.Group().NewScalar()
	for l, f_li := range r.shareFrom {
		s_i.Add(f_li)
		// TODO: Maybe actually clear this in a better way
		delete(r.shareFrom, l)
	}

	// 4. "Each Pᵢ calculates their public verification share Yᵢ = sᵢ • G,
	// and the group's public key Y = ∑ⱼ₌₁ⁿ ϕⱼ₀. Any participant
	// can compute the verification share of any other participant by calculating
	//
	// Yᵢ = ∑ⱼ₌₁ⁿ ∑ₖ₌₀ᵗ (iᵏ mod q) * ϕⱼₖ."

	Y := r.Group().NewPoint()
	for _, phi_j := range r.Phi {
		Y = Y.Add(phi_j.Constant())
	}

	VerificationShares := make(map[party.ID]curve.Point)
	// This accomplishes the same sum as in the paper, by first summing
	// together the exponent coefficients, and then evaluating.
	exponents := make([]*polynomial.Exponent, 0, r.PartyIDs().Len())
	for _, phi_j := range r.Phi {
		exponents = append(exponents, phi_j)
	}
	verificationExponent, err := polynomial.Sum(exponents)
	if err != nil {
		panic(err)
	}
	for _, i := range r.PartyIDs() {
		VerificationShares[i] = verificationExponent.Evaluate(i.Scalar(r.Group()))
	}

	if r.taproot {
		// BIP-340 adjustment: If our public key is odd, then the underlying secret
		// needs to be negated. Since this secret is ∑ᵢ aᵢ₀, we can negated each
		// of these. Had we generated the polynomials -fᵢ instead, we would have
		// ended up with the correct sharing of the secret. So, this means that
		// we can correct by simply negating our share.
		//
		// We assume that everyone else does the same, so we negate all the verification
		// shares.
		YSecp := Y.(*curve.Secp256k1Point)
		if !YSecp.HasEvenY() {
			s_i.Negate()
			for i, y_i := range VerificationShares {
				VerificationShares[i] = y_i.Negate()
			}
		}
		return &round.Output{Result: &TaprootResult{
			ID:                 r.SelfID(),
			Threshold:          r.threshold,
			PrivateShare:       s_i,
			PublicKey:          YSecp.XBytes()[:],
			VerificationShares: VerificationShares,
		}}, nil
	}

	return &round.Output{Result: &Result{
		ID:                 r.SelfID(),
		Group:              r.Group(),
		Threshold:          r.threshold,
		PrivateShare:       s_i,
		PublicKey:          Y,
		VerificationShares: VerificationShares,
	}}, nil
}

// RoundNumber implements message.Content.
func (message3) RoundNumber() round.Number { return 3 }

// MessageContent implements round.Round.
func (round3) MessageContent() round.Content { return &message3{} }

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }

// Init implements round.Content.
func (m *message3) Init(group curve.Curve) {
	m.F_li = group.NewScalar()
}
