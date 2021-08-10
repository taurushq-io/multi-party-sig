package sign

import (
	"crypto/ecdsa"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/types"
)

var _ round.Round = (*output)(nil)

type output struct {
	*round4

	// SigmaShares[j] = σⱼ = m⋅kⱼ + χⱼ⋅R|ₓ
	SigmaShares map[party.ID]*curve.Scalar

	// Delta = δ = ∑ⱼ δⱼ
	// computed from received shares
	Delta *curve.Scalar

	// BigDelta = Δ = ∑ⱼ Δⱼ
	BigDelta *curve.Point

	// R = [δ⁻¹] Γ
	BigR *curve.Point

	// R = R|ₓ
	R *curve.Scalar
}

type SignOutput struct {
	SigmaShare *curve.Scalar
}

// VerifyMessage implements round.Round.
func (r *output) VerifyMessage(_ party.ID, _ party.ID, content message.Content) error {
	body, ok := content.(*SignOutput)
	if !ok || body == nil {
		return message.ErrInvalidContent
	}

	if body.SigmaShare == nil || body.SigmaShare.IsZero() {
		return message.ErrNilContent
	}

	return nil
}

// StoreMessage implements round.Round.
//
// - save σⱼ
func (r *output) StoreMessage(from party.ID, content message.Content) error {
	body := content.(*SignOutput)
	r.SigmaShares[from] = body.SigmaShare
	return nil
}

// Finalize implements round.Round
//
// - compute σ = ∑ⱼ σⱼ
// - verify signature.
func (r *output) Finalize(chan<- *message.Message) (round.Round, error) {
	// compute σ = ∑ⱼ σⱼ
	Sigma := curve.NewScalar()
	for _, j := range r.PartyIDs() {
		Sigma.Add(Sigma, r.SigmaShares[j])
	}

	signature := &Signature{
		R: r.BigR,
		S: Sigma,
	}

	RInt, SInt := signature.ToRS()
	// Verify signature using Go's ECDSA lib
	if !ecdsa.Verify(r.PublicKey.ToPublicKey(), r.Message, RInt, SInt) {
		return nil, ErrRoundOutputValidateSigFailedECDSA
	}
	if !signature.Verify(r.PublicKey, r.Message) {
		return nil, ErrRoundOutputValidateSigFailed
	}

	return &round.Output{Result: &Result{signature}}, nil
}

func (r *output) MessageContent() message.Content {
	return &SignOutput{}
}

func (m *SignOutput) RoundNumber() types.RoundNumber {
	return 5
}
