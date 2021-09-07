package keygen

import (
	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/round"
)

// round3S is the third round from the Sender's perspective.
type round3S struct {
	*round2S
	setup *ot.CorreOTSendSetup
}

func (r *round3S) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message3R)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.OtMsg == nil {
		return round.ErrNilFields
	}
	return nil
}

func (r *round3S) StoreMessage(msg round.Message) (err error) {
	body := msg.Content.(*message3R)
	r.setup, err = r.sender.Round3(body.OtMsg)
	return
}

func (r *round3S) Finalize(out chan<- *round.Message) (round.Session, error) {
	return r.ResultRound(&ConfigSender{Setup: r.setup, SecretShare: r.secretShare, Public: r.public, ChainKey: r.chainKey}), nil
}

func (r *round3S) MessageContent() round.Content {
	return &message3R{}
}

func (round3S) Number() round.Number {
	return 3
}
