package presign

import (
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

var _ round.Round = (*sign1)(nil)

type sign1 struct {
	*round.Helper
	// PublicKey = X
	PublicKey curve.Point
	// Message = m
	Message []byte
	// PreSignature = (R, {R̄ⱼ,Sⱼ}ⱼ, kᵢ, χᵢ)
	PreSignature *ecdsa.PreSignature
}

// VerifyMessage implements round.Round.
func (r *sign1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *sign1) StoreMessage(round.Message) error { return nil }

func (r *sign1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// σᵢ = kᵢm+rχᵢ (mod q)
	SigmaShare := r.PreSignature.SignatureShare(r.Message)

	err := r.BroadcastMessage(out, &broadcastSign2{
		Sigma: SigmaShare,
	})
	if err != nil {
		return r, err.(error)
	}

	return &sign2{
		sign1:       r,
		SigmaShares: map[party.ID]curve.Scalar{r.SelfID(): SigmaShare},
	}, nil
}

// MessageContent implements round.Round.
func (sign1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (sign1) Number() round.Number { return 1 }
