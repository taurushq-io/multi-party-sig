package keygen

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

// This round corresponds with steps 2-4 of Round 2, Figure 1 in the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
type round3 struct {
	*round2

	// shareFrom is the secret share sent to us by a given party, including ourselves.
	//
	// shareFrom[l] corresponds to fₗ(i) in the Frost paper, with i our own ID.
	shareFrom map[party.ID]*curve.Scalar
}

func (r *round3) ProcessMessage(l party.ID, content message.Content) error {
	msg, ok := content.(*Keygen3)
	if !ok {
		return fmt.Errorf("failed to convert message to Keygen3: %v", msg)
	}

	// These steps come from Figure 1, Round 2 of the Frost paper

	// 2. "Each Pᵢ verifies their shares by calculating
	//
	//   fₗ(i) * G =? ∑ₖ₌₀ᵗ (iᵏ mod q) * ϕₗₖ
	//
	// aborting if the check fails."

	r.shareFrom[l] = msg.F_li

	expected := curve.NewIdentityPoint().ScalarBaseMult(r.shareFrom[l])
	actual := r.Phi[l].Evaluate(r.SelfID().Scalar())
	if !expected.Equal(actual) {
		return fmt.Errorf("VSS failed to validate")
	}

	return nil
}

func (r *round3) Finalize(chan<- *message.Message) (round.Round, error) {
	// These steps come from Figure 1, Round 2 of the Frost paper

	// 3. "Each P_i calculates their long-lived private signing share by computing
	// sᵢ = ∑ₗ₌₁ⁿ fₗ(i), stores s_i securely, and deletes each fₗ(i)"

	s_i := curve.NewScalar()
	for l, f_li := range r.shareFrom {
		s_i.Add(s_i, f_li)
		// TODO: Maybe actually clear this in a better way
		delete(r.shareFrom, l)
	}

	// 4. "Each Pᵢ calculates their public verification share Yᵢ = sᵢ • G,
	// and the group's public key Y = ∑ⱼ₌₁ⁿ ϕⱼ₀. Any participant
	// can compute the verification share of any other participant by calculating
	//
	// Yᵢ = ∑ⱼ₌₁ⁿ ∑ₖ₌₀ᵗ (iᵏ mod q) * ϕⱼₖ."

	Y := curve.NewIdentityPoint()
	for _, phi_j := range r.Phi {
		Y.Add(Y, phi_j.Constant())
	}

	VerificationShares := make(map[party.ID]*curve.Point)
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
		VerificationShares[i] = verificationExponent.Evaluate(i.Scalar())
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
		if !Y.HasEvenY() {
			s_i.Negate(s_i)
			for _, y_i := range VerificationShares {
				y_i.Negate(y_i)
			}
		}
		return &round.Output{Result: &TaprootResult{
			ID:                 r.SelfID(),
			Threshold:          r.threshold,
			PrivateShare:       s_i,
			PublicKey:          Y.XBytes()[:],
			VerificationShares: VerificationShares,
		}}, nil
	}

	return &round.Output{Result: &Result{
		ID:                 r.SelfID(),
		Threshold:          r.threshold,
		PrivateShare:       s_i,
		PublicKey:          Y,
		VerificationShares: VerificationShares,
	}}, nil
}

// MessageContent implements round.Round.
//
// Since this is the first round of the protocol, we expect to see a dummy First type.
func (r *round3) MessageContent() message.Content {
	return &Keygen3{}
}

// Validate implements message.Content.
func (m *Keygen3) Validate() error {
	if m == nil {
		return errors.New("keygen.round3: message is nil")
	}
	if m.F_li == nil {
		return errors.New("keygen.round3: a message field is nil")
	}
	return nil
}

// RoundNumber implements message.Content.
func (m *Keygen3) RoundNumber() types.RoundNumber { return 3 }
