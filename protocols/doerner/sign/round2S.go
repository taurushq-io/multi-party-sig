package sign

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
)

// round2S is the final round of the signature protocol.
type round2S struct {
	*round1S
	Sig ecdsa.Signature
}

func (r *round2S) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message2R)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if !body.Sig.Verify(r.config.Public, r.hash) {
		return errors.New("failed to verify signature")
	}
	return nil
}

func (r *round2S) StoreMessage(msg round.Message) (err error) {
	body := msg.Content.(*message2R)
	r.Sig = body.Sig
	return nil
}

func (r *round2S) Finalize(out chan<- *round.Message) (round.Session, error) {
	return r.ResultRound(&r.Sig), nil
}

func (r *round2S) MessageContent() round.Content {
	return &message2R{Sig: ecdsa.EmptySignature(r.Group())}
}

func (round2S) Number() round.Number { return 2 }
