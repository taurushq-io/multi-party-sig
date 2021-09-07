package keygen

import (
	"crypto/rand"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
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
	// refresh indicates whether or not we're doing a refresh instead of a key-generation.
	refresh bool
	// These fields are set to accomodate both key-generation, in which case they'll
	// take on identity values, and refresh, in which case their values are meaningful.
	// These values should be modifiable.

	// privateShare is our previous private share when refreshing, and 0 otherwise.
	privateShare curve.Scalar
	// verificationShares should hold the previous verification shares when refreshing, and identity points otherwise.
	verificationShares map[party.ID]curve.Point
	// publicKey should be the previous public key when refreshing, and 0 otherwise.
	publicKey curve.Point
}

// VerifyMessage implements round.Round.
//
// Since this is the start of the protocol, we aren't expecting to have received
// any messages yet, so we do nothing.
func (r *round1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
//
// The overall goal of this round is to generate a secret value, create a polynomial
// sharing of that value, and then send commitments to these values.
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	group := r.Group()
	// These steps come from Figure 1, Round 1 of the Frost paper.

	// 1. "Every participant P_i samples t + 1 random values (aᵢ₀, ..., aᵢₜ)) <-$ Z/(q)
	// and uses these values as coefficients to define a degree t polynomial
	// fᵢ(x) = ∑ⱼ₌₀ᵗ⁻¹ aᵢⱼ xʲ"
	//
	// Note: I've adjusted the thresholds in this quote to reflect our convention
	// that t + 1 participants are needed to create a signature.

	// Refresh: Instead of creating a new secret, instead use 0, so that our result doesn't change.
	a_i0 := group.NewScalar()
	a_i0_times_G := group.NewPoint()
	if !r.refresh {
		a_i0 = sample.Scalar(rand.Reader, r.Group())
		a_i0_times_G = a_i0.ActOnBase()
	}
	f_i := polynomial.NewPolynomial(r.Group(), r.threshold, a_i0)

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

	// Refresh: Don't create a proof.
	var Sigma_i *zksch.Proof
	if !r.refresh {
		Sigma_i = zksch.NewProof(r.Helper.HashForID(r.SelfID()), a_i0_times_G, a_i0, nil)
	}

	// 3. "Every participant Pᵢ computes a public comment Φᵢ = <ϕᵢ₀, ..., ϕᵢₜ>
	// where ϕᵢⱼ = aᵢⱼ * G."
	//
	// Note: I've once again adjusted the threshold indices, I've also taken
	// the liberty of renaming "Cᵢ" to "Φᵢ" so that we can later do Phi_i[j]
	// for each individual commitment.

	// This method conveniently calculates all of that for us
	// Phi_i = Φᵢ
	Phi_i := polynomial.NewPolynomialExponent(f_i)

	// c_i is our contribution to the chaining key
	c_i, err := types.NewRID(rand.Reader)
	if err != nil {
		return r, fmt.Errorf("failed to sample ChainKey")
	}
	commitment, decommitment, err := r.HashForID(r.SelfID()).Commit(c_i)
	if err != nil {
		return r, fmt.Errorf("failed to commit to chain key")
	}

	// 4. "Every Pᵢ broadcasts Φᵢ, σᵢ to all other participants
	err = r.BroadcastMessage(out, &broadcast2{
		Phi_i:      Phi_i,
		Sigma_i:    Sigma_i,
		Commitment: commitment,
	})
	if err != nil {
		return r, err
	}

	return &round2{
		round1:               r,
		f_i:                  f_i,
		Phi:                  map[party.ID]*polynomial.Exponent{r.SelfID(): Phi_i},
		ChainKeys:            map[party.ID]types.RID{r.SelfID(): c_i},
		ChainKeyDecommitment: decommitment,
		ChainKeyCommitments:  make(map[party.ID]hash.Commitment),
	}, nil
}

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }
