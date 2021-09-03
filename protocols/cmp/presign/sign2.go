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

type broadcastSign2 struct {
	round.NormalBroadcastContent
	// Sigma = σᵢ
	Sigma curve.Scalar
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - save σⱼ.
func (r *sign2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcastSign2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.Sigma.IsZero() {
		return round.ErrNilFields
	}

	r.SigmaShares[msg.From] = body.Sigma
	return nil
}

// VerifyMessage implements round.Round.
func (sign2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (sign2) StoreMessage(round.Message) error { return nil }

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
func (sign2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcastSign2) RoundNumber() round.Number { return 8 }

// BroadcastContent implements round.BroadcastRound.
func (r *sign2) BroadcastContent() round.BroadcastContent {
	return &broadcastSign2{
		Sigma: r.Group().NewScalar(),
	}
}

// Number implements round.Round.
func (sign2) Number() round.Number { return 8 }
