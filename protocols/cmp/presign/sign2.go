package presign

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

var _ round.Round = (*sign2)(nil)

type sign2 struct {
	*sign1
	// SigmaShares[j] = σⱼ
	SigmaShares map[party.ID]curve.Scalar
}

type messageSign2 struct {
	// Sigma = σᵢ
	Sigma curve.Scalar
}

// VerifyMessage implements round.Round.
func (r *sign2) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*messageSign2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.Sigma.IsZero() {
		return round.ErrNilFields
	}
	return nil
}

// StoreMessage implements round.Round.
//
// - save σⱼ.
func (r *sign2) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*messageSign2)
	r.SigmaShares[from] = body.Sigma
	return nil
}

// Finalize implements round.Round
//
// - verify (r,s)
// - if not, find culprit.
func (r *sign2) Finalize(chan<- *round.Message) (round.Session, error) {
	s := r.PreSignature.Signature(r.SigmaShares)

	if s.Verify(r.PublicKey, r.Message) {
		return r.ResultRound(s), nil
	}

	culprits := r.PreSignature.VerifySignatureShares(r.SigmaShares, r.Message)
	return r.AbortRound(errors.New("signature failed to verify"), culprits...), nil
}

// MessageContent implements round.Round.
func (r *sign2) MessageContent() round.Content {
	return &messageSign2{
		Sigma: r.Group().NewScalar(),
	}
}

// Number implements round.Round.
func (sign2) Number() round.Number { return 2 }
