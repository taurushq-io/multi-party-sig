package sign

import (
	"crypto/ecdsa"
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

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

// ProcessMessage implements round.Round
//
// - σⱼ != 0
func (r *output) ProcessMessage(j party.ID, content message.Content) error {
	body := content.(*SignOutput)

	if body.SigmaShare.IsZero() {
		return ErrRoundOutputSigmaZero
	}
	r.SigmaShares[j] = body.SigmaShare
	return nil
}

// Finalize implements round.Round
//
// - compute σ = ∑ⱼ σⱼ
// - verify signature
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
	if !ecdsa.Verify(r.PublicKey, r.Message, RInt, SInt) {
		return nil, ErrRoundOutputValidateSigFailedECDSA
	}
	pk := curve.FromPublicKey(r.PublicKey)
	if !signature.Verify(pk, r.Message) {
		return nil, ErrRoundOutputValidateSigFailed
	}

	return &round.Output{Result: &Result{signature}}, nil
}

func (r *output) MessageContent() message.Content {
	return &SignOutput{}
}

func (m *SignOutput) Validate() error {
	if m == nil {
		return errors.New("sign.round4: message is nil")
	}
	if m.SigmaShare == nil {
		return errors.New("sign.round4: message contains nil fields")
	}
	return nil
}

func (m *SignOutput) RoundNumber() types.RoundNumber {
	return 5
}
