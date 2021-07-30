package sign

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/internal/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol/types"
	"github.com/taurusgroup/cmp-ecdsa/pkg/taproot"
)

// This corresponds with step 7 of Figure 3 in the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
//
// The big difference, once again, stems from their being no signing authority.
// Instead, each participant calculates the signature on their own.
type round3 struct {
	*round2
	// R is the group commitment, and the first part of the consortium signature
	R *curve.Point
	// RShares is the fraction each participant contributes to the group commitment
	//
	// This corresponds to R_i in the Frost paper
	RShares map[party.ID]*curve.Point
	// c is the challenge, computed as H(R, Y, m).
	c *curve.Scalar
	// z contains the response from each participant
	//
	// z[i] corresponds to zᵢ in the Frost paper
	z map[party.ID]*curve.Scalar

	// Lambda contains all Lagrange coefficients of the parties participating in this session.
	// Lambda[l] = λₗ
	Lambda map[party.ID]*curve.Scalar
}

// ProcessMessage implements round.Round.
func (r *round3) ProcessMessage(l party.ID, content message.Content) error {
	msg, ok := content.(*Sign3)
	if !ok {
		return fmt.Errorf("failed to convert message to Sign3: %v", msg)
	}

	// These steps come from Figure 3 of the Frost paper.

	// 7.b "Verify the validity of each response by checking
	//
	//    zᵢ • G = Rᵢ + c * λᵢ * Yᵢ
	//
	// for each share zᵢ, i in S. If the equality does not hold, identify and report the
	// misbehaving participant, and then abort. Otherwise, continue."
	//
	// Note that step 7.a is an artifact of having a signing authority. In our case,
	// we've already computed everything that step computes.

	expected := curve.NewIdentityPoint()
	expected.ScalarMult(r.Lambda[l], r.YShares[l])
	expected.ScalarMult(r.c, expected)
	expected.Add(r.RShares[l], expected)

	actual := curve.NewIdentityPoint().ScalarBaseMult(msg.Z_i)

	if !actual.Equal(expected) {
		return fmt.Errorf("failed to verify response from %v", l)
	}

	r.z[l] = msg.Z_i

	return nil
}

// Finalize implements round.Round.
func (r *round3) Finalize(chan<- *message.Message) (round.Round, error) {
	// These steps come from Figure 3 of the Frost paper.

	// 7.c "Compute the group's response z = ∑ᵢ zᵢ"
	z := curve.NewScalar()
	for _, z_l := range r.z {
		z.Add(z, z_l)
	}

	// The format of our signature depends on using taproot, naturally
	if r.taproot {
		sig := taproot.Signature(make([]byte, 0, taproot.SignatureLen))
		sig = append(sig, r.R.XBytes()[:]...)
		zBytes := z.Bytes()
		sig = append(sig, zBytes[:]...)

		taprootPub := taproot.PublicKey(r.Y.XBytes()[:])

		if !taprootPub.Verify(sig, r.M) {
			return r, fmt.Errorf("generated signature failed to verify")
		}

		return &round.Output{Result: sig}, nil
	} else {
		sig := Signature{
			R: r.R,
			z: z,
		}

		if !sig.Verify(r.Y, r.M) {
			return r, fmt.Errorf("generated signature failed to verify")
		}

		return &round.Output{Result: sig}, nil
	}
}

// MessageContent implements round.Round.
func (r *round3) MessageContent() message.Content {
	return &Sign3{}
}

// Validate implements message.Content.
func (m *Sign3) Validate() error {
	return nil
}

// RoundNumber implements message.Content.
func (m *Sign3) RoundNumber() types.RoundNumber { return 3 }
