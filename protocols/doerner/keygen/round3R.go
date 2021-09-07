package keygen

import (
	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/round"
)

// message3R is the message sent by the Receiver at the start of the third round.
type message3R struct {
	OtMsg *ot.CorreOTSetupReceiveRound3Message
}

func (message3R) RoundNumber() round.Number { return 3 }

// round3R is the third round from the Receiver's perspective.
type round3R struct {
	*round2R
	setup *ot.CorreOTReceiveSetup
	otMsg *ot.CorreOTSetupReceiveRound3Message
}

func (r *round3R) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message2S)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.OtMsg == nil {
		return round.ErrNilFields
	}
	return nil
}

func (r *round3R) StoreMessage(msg round.Message) (err error) {
	body := msg.Content.(*message2S)
	r.otMsg, r.setup, err = r.receiver.Round3(body.OtMsg)
	return
}

func (r *round3R) Finalize(out chan<- *round.Message) (round.Session, error) {
	if err := r.SendMessage(out, &message3R{r.otMsg}, ""); err != nil {
		return r, err
	}
	return r.ResultRound(&ConfigReceiver{Setup: r.setup, SecretShare: r.secretShare, Public: r.public, ChainKey: r.chainKey}), nil
}

func (r *round3R) MessageContent() round.Content {
	return &message2S{}
}

func (round3R) Number() round.Number {
	return 3
}
