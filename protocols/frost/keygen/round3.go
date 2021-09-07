package keygen

import (
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
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
}

type broadcast3 struct {
	round.NormalBroadcastContent
	// C_l is contribution to the chaining key for this party.
	C_l types.RID
	// Decommitment = uᵢ decommitment bytes
	Decommitment hash.Decommitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if err := body.C_l.Validate(); err != nil {
		return err
	}

	// Verify that the commitment to the chain key contribution matches, and then xor
	// it into the accumulated chain key so far.
	if !r.HashForID(from).Decommit(r.ChainKeyCommitments[from], body.Decommitment, body.C_l) {
		return fmt.Errorf("failed to verify chain key commitment")
	}
	r.ChainKeys[from] = body.C_l
	return nil
}

// VerifyMessage implements round.Round.
func (r *round3) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// check nil
	if body.F_li == nil {
		return round.ErrNilFields
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

	return nil
}

// Finalize implements round.Round.
func (r *round3) Finalize(chan<- *round.Message) (round.Session, error) {
	ChainKey := types.EmptyRID()
	for _, j := range r.PartyIDs() {
		ChainKey.XOR(r.ChainKeys[j])
	}

	// These steps come from Figure 1, Round 2 of the Frost paper

	// 3. "Each P_i calculates their long-lived private signing share by computing
	// sᵢ = ∑ₗ₌₁ⁿ fₗ(i), stores s_i securely, and deletes each fₗ(i)"

	for l, f_li := range r.shareFrom {
		r.privateShare.Add(f_li)
		// TODO: Maybe actually clear this in a better way
		delete(r.shareFrom, l)
	}

	// 4. "Each Pᵢ calculates their public verification share Yᵢ = sᵢ • G,
	// and the group's public key Y = ∑ⱼ₌₁ⁿ ϕⱼ₀. Any participant
	// can compute the verification share of any other participant by calculating
	//
	// Yᵢ = ∑ⱼ₌₁ⁿ ∑ₖ₌₀ᵗ (iᵏ mod q) * ϕⱼₖ."

	for _, phi_j := range r.Phi {
		r.publicKey = r.publicKey.Add(phi_j.Constant())
	}

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
	for k, v := range r.verificationShares {
		r.verificationShares[k] = v.Add(verificationExponent.Evaluate(k.Scalar(r.Group())))
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
		YSecp := r.publicKey.(*curve.Secp256k1Point)
		if !YSecp.HasEvenY() {
			r.privateShare.Negate()
			for i, y_i := range r.verificationShares {
				r.verificationShares[i] = y_i.Negate()
			}
		}
		secpVerificationShares := make(map[party.ID]*curve.Secp256k1Point)
		for k, v := range r.verificationShares {
			secpVerificationShares[k] = v.(*curve.Secp256k1Point)
		}
		return r.ResultRound(&TaprootConfig{
			ID:                 r.SelfID(),
			Threshold:          r.threshold,
			PrivateShare:       r.privateShare.(*curve.Secp256k1Scalar),
			PublicKey:          YSecp.XBytes()[:],
			VerificationShares: secpVerificationShares,
		}), nil
	}

	return r.ResultRound(&Config{
		ID:                 r.SelfID(),
		Threshold:          r.threshold,
		PrivateShare:       r.privateShare,
		PublicKey:          r.publicKey,
		VerificationShares: party.NewPointMap(r.verificationShares),
	}), nil
}

// RoundNumber implements round.Content.
func (message3) RoundNumber() round.Number { return 3 }

// MessageContent implements round.Round.
func (r *round3) MessageContent() round.Content {
	return &message3{
		F_li: r.Group().NewScalar(),
	}
}

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent { return &broadcast3{} }

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }
