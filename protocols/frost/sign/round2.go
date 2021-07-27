package sign

import (
	fmt "fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
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
	// d_i is the first nonce we've created.
	d_i *curve.Scalar
	// e_i is the second nonce we've created.
	e_i *curve.Scalar
	// D will contain all of the commitments created by each party, ourself included.
	D map[party.ID]*curve.Point
	// E will contain all of the commitments created by each party, ourself included.
	E map[party.ID]*curve.Point
}

// ProcessMessage implements round.Round.
func (r *round2) ProcessMessage(l party.ID, content message.Content) error {
	msg, ok := content.(*Sign2)
	if !ok {
		return fmt.Errorf("failed to convert message to Sign2: %v", msg)
	}

	// This section roughly follows Figure 3.

	// 3. "After receiving (m, B), each P_i first validates the message m,
	// and then checks D_l, E_l in G^* for each commitment in B, aborting if
	// either check fails."
	//
	// We make a few deparatures.
	//
	// We implicitly assume that the message validation has happened before
	// calling this protocol.
	//
	// We also receive each D_l, E_l from the participant l directly, instead of
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

	// 4. "Each P_i then computes the set of binding values p_l = H_1(l, m, B).
	// Each P_i then derives the group commitment R = sum_l D_l + rho_l * E_l and
	// the challenge c = H_2(R, Y, m)."
	//
	// It's easier to calculate H(m, B, l), that way we can simply clone the hash
	// state after H(m, B), instead of rehashing them each time.
	//
	// We also use a hash of the message, instead of the message directly.

	rho := make(map[party.ID]*curve.Scalar)
	// This calculates H(m, B), allowing us to avoid re-hashing this data for
	// each extra party l.
	rhoPreHash := hash.New()
	rhoPreHash.WriteAny(r.M)
	for _, D_l := range r.D {
		rhoPreHash.WriteAny(D_l)
	}
	for _, E_l := range r.E {
		rhoPreHash.WriteAny(E_l)
	}
	for _, l := range r.PartyIDs() {
		rhoHash := rhoPreHash.Clone()
		rhoHash.WriteAny(l)
		rho[l] = sample.Scalar(rhoHash)
	}

	R := curve.NewIdentityPoint()
	RShares := make(map[party.ID]*curve.Point)
	for _, l := range r.PartyIDs() {
		RShares[l] = curve.NewIdentityPoint()
		RShares[l].ScalarMult(rho[l], r.E[l])
		RShares[l].Add(RShares[l], r.D[l])
		R.Add(R, RShares[l])
	}

	cHash := hash.New()
	cHash.WriteAny(R, r.Y, r.M)
	c := sample.Scalar(cHash)

	// 5. "Each P_i computes their response using their long-lived secret share s_i
	// by computing z_i = d_i + (e_i rho_i) + lambda_i s_i c, using S to determine
	// the ith lagrange coefficient lambda_i"

	z_i := r.PartyIDs().Lagrange(r.SelfID())
	z_i.Multiply(z_i, r.s_i)
	z_i.Multiply(z_i, c)
	z_i.Add(z_i, r.d_i)
	z_i.MultiplyAdd(r.e_i, rho[r.SelfID()], z_i)

	// 6. "Each P_i securely deletes ((d_i, D_i), (e_i, E_i)) from their local storage,
	// and returns z_i to SA."
	//
	// Since we don't have a signing authority, we instead broadcast z_i.

	// TODO: Securely delete the nonces.

	// Broadcast our response
	msg := r.MarshalMessage(&Sign3{z_i: z_i})
	if err := r.SendMessage(msg, out); err != nil {
		return r, err
	}

	z := make(map[party.ID]*curve.Scalar)
	z[r.SelfID()] = z_i

	return &round3{
		round2:  r,
		R:       R,
		RShares: RShares,
		c:       c,
		z:       z,
	}, nil
}

// MessageContent implements round.Round.
func (r *round2) MessageContent() message.Content {
	return &Sign2{}
}

// Validate implements message.Content
func (m *Sign2) Validate() error {
	return nil
}

// RoundNumber implements message.Content
func (m *Sign2) RoundNumber() types.RoundNumber { return 2 }
