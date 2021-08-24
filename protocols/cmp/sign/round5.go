package sign

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

var _ round.Round = (*round5)(nil)

type round5 struct {
	*round4

	// SigmaShares[j] = σⱼ = m⋅kⱼ + χⱼ⋅R|ₓ
	SigmaShares map[party.ID]curve.Scalar

	// Delta = δ = ∑ⱼ δⱼ
	// computed from received shares
	Delta curve.Scalar

	// BigDelta = Δ = ∑ⱼ Δⱼ
	BigDelta curve.Point

	// R = [δ⁻¹] Γ
	BigR curve.Point

	// R = R|ₓ
	R curve.Scalar
}

type message5 struct {
	SigmaShare curve.Scalar
}

// VerifyMessage implements round.Round.
func (r *round5) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message5)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.SigmaShare == nil || body.SigmaShare.IsZero() {
		return round.ErrNilFields
	}

	return nil
}

// StoreMessage implements round.Round.
//
// - save σⱼ
func (r *round5) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*message5)
	r.SigmaShares[from] = body.SigmaShare
	return nil
}

// Finalize implements round.Round
//
// - compute σ = ∑ⱼ σⱼ
// - verify signature.
func (r *round5) Finalize(chan<- *round.Message) (round.Session, error) {
	// compute σ = ∑ⱼ σⱼ
	Sigma := r.Group().NewScalar()
	for _, j := range r.PartyIDs() {
		Sigma.Add(r.SigmaShares[j])
	}

	signature := &ecdsa.Signature{
		R: r.BigR,
		S: Sigma,
	}

	if !signature.Verify(r.PublicKey, r.Message) {
		return nil, errors.New("failed to validate signature")
	}

	return &round.Output{Result: signature}, nil
}

// MessageContent implements round.Round.
func (round5) MessageContent() round.Content { return &message5{} }

// Number implements round.Round.
func (round5) Number() round.Number { return 5 }

// Init implements round.Content.
func (m *message5) Init(group curve.Curve) {
	m.SigmaShare = group.NewScalar()
}
