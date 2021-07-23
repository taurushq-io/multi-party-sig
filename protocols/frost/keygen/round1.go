package keygen

import (
	"crypto/rand"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

// This round corresponds with the steps 1-4 of Round 1, Figure 1 in the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
type round1 struct {
	*round.Helper

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

	// 1. "Every participant P_i samples t + 1 random values (a_i0, ..., ait)) <-$ Z/(q)
	// and uses these values as coefficients to define a degree t polynomial
	// f_i(x) = sum_{j = 0}^{t - 1} a_ij x^j"
	//
	// Note: I've adjusted the thresholds in this quote to reflect our convention
	// that t + 1 participants are needed to create a signature.
	a_i0 := sample.Scalar(rand.Reader)
	a_i := polynomial.NewPolynomial(r.threshold, a_i0)

	// 2. "Every P_i computes a proof of knowledge to the corresponding secret a_i0
	// by calculating sigma_i = (R_i, mu_i), such that:
	//
	//   k <-$ Z/(q)
	//   R_i = k * G
	//   c_i = H(i, ctx, a_i0 * G, R_i)
	//   mu_i = k + a_i0 c_i
	//
	// with ctx being a context string to prevent replay attacks"

	// We essentially follow this, although the order of hashing ends up being slightly
	// different.
	k := sample.Scalar(rand.Reader)
	R_i := curve.NewIdentityPoint().ScalarBaseMult(k)
	a_i0_times_G := curve.NewIdentityPoint().ScalarBaseMult(a_i0)
	// At this point, we've already hashed context inside of helper, so we just
	// add in our own ID, and then we're good to go.
	mu_i := zksch.Prove(r.Helper.HashForID(r.SelfID()), R_i, a_i0_times_G, k, a_i0)

	// 3. "Every participant P_i computes a public comment Phi_i = <phi_i0, ..., phi_it>
	// where phi_ij = a_ij * G."
	//
	// Note: I've once again adjusted the threshold indices, I've also taken
	// the liberty of renaming "C_i" to "Phi_i" so that we can later do Phi_i[j]
	// for each individual commitment.

	// This method conveniently calculates all of that for us
	Phi_i := polynomial.NewPolynomialExponent(a_i)

	// 4. "Every P_i broadcasts Phi_i, sigma_i to all other participants"
	msg := r.MarshalMessage(&Keygen2{Phi_i, R_i, mu_i})
	if err := r.SendMessage(msg, out); err != nil {
		return r, err
	}

	return &round2{round1: r}, nil
}

// MessageContent implements round.Round.
//
// Since this is the first round of the protocol, we expect to see a dummy First type.
func (r *round1) MessageContent() message.Content {
	return &message.First{}
}
