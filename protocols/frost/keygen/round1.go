package keygen

import (
	"crypto/rand"

	"github.com/taurusgroup/cmp-ecdsa/internal/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol/message"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

// This round corresponds with the steps 1-4 of Round 1, Figure 1 in the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
type round1 struct {
	*round.Helper
	// taproot indicates whether or not to make taproot compatible keys.
	//
	// This means taking the necessary steps to ensure that the shared secret generates
	// a public key with even y coordinate.
	//
	// We also end up returning a different result, to accomodate this fact.
	taproot bool
	// threshold is the integer t which defines the maximum number of corruptions tolerated for this session.
	//
	// Alternatively, the degree of the polynomial used to share the secret.
	//
	// Alternatively, t + 1 participants are needed to make a signature.
	threshold int
}

// ProcessMessage implements round.Round.
//
// Since this is the start of the protocol, we aren't expecting to have received
// any messages yet, so we do nothing.
func (r *round1) ProcessMessage(party.ID, message.Content) error { return nil }

// Finalize implements round.Round.
//
// The overall goal of this round is to generate a secret value, create a polynomial
// sharing of that value, and then send commitments to these values.
func (r *round1) Finalize(out chan<- *message.Message) (round.Round, error) {
	// These steps come from Figure 1, Round 1 of the Frost paper.

	// 1. "Every participant P_i samples t + 1 random values (aᵢ₀, ..., aᵢₜ)) <-$ Z/(q)
	// and uses these values as coefficients to define a degree t polynomial
	// fᵢ(x) = ∑ⱼ₌₀ᵗ⁻¹ aᵢⱼ xʲ"
	//
	// Note: I've adjusted the thresholds in this quote to reflect our convention
	// that t + 1 participants are needed to create a signature.
	a_i0 := sample.Scalar(rand.Reader)
	a_i0_times_G := curve.NewIdentityPoint().ScalarBaseMult(a_i0)
	f_i := polynomial.NewPolynomial(r.threshold, a_i0)

	// 2. "Every Pᵢ computes a proof of knowledge to the corresponding secret aᵢ₀
	// by calculating σᵢ = (Rᵢ, μᵢ), such that:
	//
	//   k <-$ Z/(q)
	//   Rᵢ = k * G
	//   cᵢ = H(i, ctx, aᵢ₀ • G, Rᵢ)
	//   μᵢ = k + aᵢ₀ cᵢ
	//
	// with ctx being a context string to prevent replay attacks"

	// We essentially follow this, although the order of hashing ends up being slightly
	// different.
	// At this point, we've already hashed context inside of helper, so we just
	// add in our own ID, and then we're good to go.
	Sigma_i := zksch.NewProof(r.Helper.HashForID(r.SelfID()), a_i0_times_G, a_i0)

	// 3. "Every participant Pᵢ computes a public comment Φᵢ = <ϕᵢ₀, ..., ϕᵢₜ>
	// where ϕᵢⱼ = aᵢⱼ * G."
	//
	// Note: I've once again adjusted the threshold indices, I've also taken
	// the liberty of renaming "Cᵢ" to "Φᵢ" so that we can later do Phi_i[j]
	// for each individual commitment.

	// This method conveniently calculates all of that for us
	// Phi_i = Φᵢ
	Phi_i := polynomial.NewPolynomialExponent(f_i)

	// 4. "Every Pᵢ broadcasts Φᵢ, σᵢ to all other participants
	msg := r.MarshalMessage(&Keygen2{Phi_i, Sigma_i})
	if err := r.SendMessage(msg, out); err != nil {
		return r, err
	}

	Phi := make(map[party.ID]*polynomial.Exponent)
	Phi[r.SelfID()] = Phi_i
	return &round2{round1: r, f_i: f_i, Phi: Phi}, nil
}

// MessageContent implements round.Round.
//
// Since this is the first round of the protocol, we expect to see a dummy First type.
func (r *round1) MessageContent() message.Content {
	return &message.First{}
}
