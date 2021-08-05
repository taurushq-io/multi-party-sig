package sign

import (
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/types"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
)

// This round roughly corresponds with steps 3-6 of Figure 3 in the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
//
// The main differences stem from the lack of a signature authority.
//
// This means that instead of receiving a bundle of all the commitments, instead
// each participant sends us their commitment directly.
//
// Then, instead of sending our scalar response to the authority, we broadcast it
// to everyone instead.
type round2 struct {
	*round1
	// d_i = dᵢ is the first nonce we've created.
	d_i *curve.Scalar
	// e_i = eᵢ is the second nonce we've created.
	e_i *curve.Scalar
	// D[i] = Dᵢ will contain all of the commitments created by each party, ourself included.
	D map[party.ID]*curve.Point
	// E[i] = Eᵢ will contain all of the commitments created by each party, ourself included.
	E map[party.ID]*curve.Point
}

// ProcessMessage implements round.Round.
func (r *round2) ProcessMessage(l party.ID, content message.Content) error {
	msg, ok := content.(*Sign2)
	if !ok {
		return fmt.Errorf("failed to convert message to Sign2: %v", msg)
	}

	// This section roughly follows Figure 3.

	// 3. "After receiving (m, B), each Pᵢ first validates the message m,
	// and then checks Dₗ, Eₗ in Gˣ for each commitment in B, aborting if
	// either check fails."
	//
	// We make a few departures.
	//
	// We implicitly assume that the message validation has happened before
	// calling this protocol.
	//
	// We also receive each Dₗ, Eₗ from the participant l directly, instead of
	// an entire bundle from a signing authority.
	if msg.D_i.IsIdentity() || msg.E_i.IsIdentity() {
		return fmt.Errorf("nonce commitment is the identity point")
	}

	r.D[l] = msg.D_i
	r.E[l] = msg.E_i

	return nil
}

// Finalize implements round.Round.
func (r *round2) Finalize(out chan<- *message.Message) (round.Round, error) {
	// This essentially follows parts of Figure 3.

	// 4. "Each Pᵢ then computes the set of binding values ρₗ = H₁(l, m, B).
	// Each Pᵢ then derives the group commitment R = ∑ₗ Dₗ + ρₗ * Eₗ and
	// the challenge c = H₂(R, Y, m)."
	//
	// It's easier to calculate H(m, B, l), that way we can simply clone the hash
	// state after H(m, B), instead of rehashing them each time.
	//
	// We also use a hash of the message, instead of the message directly.

	rho := make(map[party.ID]*curve.Scalar)
	// This calculates H(m, B), allowing us to avoid re-hashing this data for
	// each extra party l.
	rhoPreHash := hash.New()
	_ = rhoPreHash.WriteAny(r.M)
	for _, l := range r.PartyIDs() {
		_ = rhoPreHash.WriteAny(r.D[l], r.E[l])
	}
	for _, l := range r.PartyIDs() {
		rhoHash := rhoPreHash.Clone()
		_ = rhoHash.WriteAny(l)
		rho[l] = sample.Scalar(rhoHash.Digest())
	}

	R := curve.NewIdentityPoint()
	RShares := make(map[party.ID]*curve.Point)
	for _, l := range r.PartyIDs() {
		RShares[l] = curve.NewIdentityPoint()
		RShares[l].ScalarMult(rho[l], r.E[l])
		RShares[l].Add(RShares[l], r.D[l])
		R.Add(R, RShares[l])
	}
	var c *curve.Scalar
	if r.taproot {
		// BIP-340 adjustment: We need R to have an even y coordinate. This means
		// conditionally negating k = ∑ᵢ (dᵢ + (eᵢ ρᵢ)), which we can accomplish
		// by negating our dᵢ, eᵢ, if necessary. This entails negating the RShares
		// as well.
		if !R.HasEvenY() {
			r.d_i.Negate(r.d_i)
			r.e_i.Negate(r.e_i)
			for _, l := range r.PartyIDs() {
				RShares[l].Negate(RShares[l])
			}
		}

		// BIP-340 adjustment: we need to calculate our hash as specified in:
		// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing
		RBytes := R.XBytes()[:]
		PBytes := r.Y.XBytes()[:]
		cHash := taproot.TaggedHash("BIP0340/challenge", RBytes, PBytes, r.M)
		c, _ = curve.NewScalar().SetBytes(cHash)
	} else {
		cHash := hash.New()
		_ = cHash.WriteAny(R, r.Y, r.M)
		c = sample.Scalar(cHash.Digest())
	}

	// Lambdas[i] = λᵢ
	Lambdas := polynomial.Lagrange(r.PartyIDs())
	// 5. "Each Pᵢ computes their response using their long-lived secret share sᵢ
	// by computing zᵢ = dᵢ + (eᵢ ρᵢ) + λᵢ sᵢ c, using S to determine
	// the ith lagrange coefficient λᵢ"
	z_i := curve.NewScalar().Multiply(Lambdas[r.SelfID()], r.s_i)
	z_i.Multiply(z_i, c)
	z_i.Add(z_i, r.d_i)
	z_i.MultiplyAdd(r.e_i, rho[r.SelfID()], z_i)

	// 6. "Each Pᵢ securely deletes ((dᵢ, Dᵢ), (eᵢ, Eᵢ)) from their local storage,
	// and returns zᵢ to SA."
	//
	// Since we don't have a signing authority, we instead broadcast zᵢ.

	// TODO: Securely delete the nonces.

	// Broadcast our response
	msg := r.MarshalMessage(&Sign3{Z_i: z_i})
	if err := r.SendMessage(msg, out); err != nil {
		return r, err
	}

	return &round3{
		round2:  r,
		R:       R,
		RShares: RShares,
		c:       c,
		z:       map[party.ID]*curve.Scalar{r.SelfID(): z_i},
		Lambda:  Lambdas,
	}, nil
}

// MessageContent implements round.Round.
func (r *round2) MessageContent() message.Content {
	return &Sign2{}
}

// Validate implements message.Content.
func (m *Sign2) Validate() error {
	return nil
}

// RoundNumber implements message.Content.
func (m *Sign2) RoundNumber() types.RoundNumber { return 2 }
