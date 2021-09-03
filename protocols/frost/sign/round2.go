package sign

import (
	"fmt"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
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
	d_i curve.Scalar
	// e_i = eᵢ is the second nonce we've created.
	e_i curve.Scalar
	// D[i] = Dᵢ will contain all of the commitments created by each party, ourself included.
	D map[party.ID]curve.Point
	// E[i] = Eᵢ will contain all of the commitments created by each party, ourself included.
	E map[party.ID]curve.Point
}

type broadcast2 struct {
	round.ReliableBroadcastContent
	// D_i is the first commitment produced by the sender of this message.
	D_i curve.Point
	// E_i is the second commitment produced by the sender of this message.
	E_i curve.Point
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
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
	if body.D_i.IsIdentity() || body.E_i.IsIdentity() {
		return fmt.Errorf("nonce commitment is the identity point")
	}

	r.D[msg.From] = body.D_i
	r.E[msg.From] = body.E_i
	return nil
}

// VerifyMessage implements round.Round.
func (round2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// This essentially follows parts of Figure 3.

	// 4. "Each Pᵢ then computes the set of binding values ρₗ = H₁(l, m, B).
	// Each Pᵢ then derives the group commitment R = ∑ₗ Dₗ + ρₗ * Eₗ and
	// the challenge c = H₂(R, Y, m)."
	//
	// It's easier to calculate H(m, B, l), that way we can simply clone the hash
	// state after H(m, B), instead of rehashing them each time.
	//
	// We also use a hash of the message, instead of the message directly.

	rho := make(map[party.ID]curve.Scalar)
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
		rho[l] = sample.Scalar(rhoHash.Digest(), r.Group())
	}

	R := r.Group().NewPoint()
	RShares := make(map[party.ID]curve.Point)
	for _, l := range r.PartyIDs() {
		RShares[l] = rho[l].Act(r.E[l])
		RShares[l] = RShares[l].Add(r.D[l])
		R = R.Add(RShares[l])
	}
	var c curve.Scalar
	if r.taproot {
		// BIP-340 adjustment: We need R to have an even y coordinate. This means
		// conditionally negating k = ∑ᵢ (dᵢ + (eᵢ ρᵢ)), which we can accomplish
		// by negating our dᵢ, eᵢ, if necessary. This entails negating the RShares
		// as well.
		RSecp := R.(*curve.Secp256k1Point)
		if !RSecp.HasEvenY() {
			r.d_i.Negate()
			r.e_i.Negate()
			for _, l := range r.PartyIDs() {
				RShares[l] = RShares[l].Negate()
			}
		}

		// BIP-340 adjustment: we need to calculate our hash as specified in:
		// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing
		RBytes := RSecp.XBytes()
		PBytes := r.Y.(*curve.Secp256k1Point).XBytes()
		cHash := taproot.TaggedHash("BIP0340/challenge", RBytes, PBytes, r.M)
		c = r.Group().NewScalar().SetNat(new(safenum.Nat).SetBytes(cHash))
	} else {
		cHash := hash.New()
		_ = cHash.WriteAny(R, r.Y, r.M)
		c = sample.Scalar(cHash.Digest(), r.Group())
	}

	// Lambdas[i] = λᵢ
	Lambdas := polynomial.Lagrange(r.Group(), r.PartyIDs())
	// 5. "Each Pᵢ computes their response using their long-lived secret share sᵢ
	// by computing zᵢ = dᵢ + (eᵢ ρᵢ) + λᵢ sᵢ c, using S to determine
	// the ith lagrange coefficient λᵢ"
	z_i := r.Group().NewScalar().Set(Lambdas[r.SelfID()]).Mul(r.s_i).Mul(c)
	z_i.Add(r.d_i)
	ed := r.Group().NewScalar().Set(rho[r.SelfID()]).Mul(r.e_i)
	z_i.Add(ed)

	// 6. "Each Pᵢ securely deletes ((dᵢ, Dᵢ), (eᵢ, Eᵢ)) from their local storage,
	// and returns zᵢ to SA."
	//
	// Since we don't have a signing authority, we instead broadcast zᵢ.

	// TODO: Securely delete the nonces.

	// Broadcast our response
	err := r.BroadcastMessage(out, &broadcast3{Z_i: z_i})
	if err != nil {
		return r, err
	}

	return &round3{
		round2:  r,
		R:       R,
		RShares: RShares,
		c:       c,
		z:       map[party.ID]curve.Scalar{r.SelfID(): z_i},
		Lambda:  Lambdas,
	}, nil
}

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &broadcast2{
		D_i: r.Group().NewPoint(),
		E_i: r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }
