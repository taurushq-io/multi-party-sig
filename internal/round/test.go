package round

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func ProcessRounds(group curve.Curve, rounds map[party.ID]Round) error {
	N := len(rounds)
	// get the second set of  messages
	out := make(chan *Message, N*N)
	for idJ, r := range rounds {
		newRound, err := r.Finalize(out)
		if err != nil {
			return err
		}
		if newRound != nil {
			rounds[idJ] = newRound
		}
	}
	close(out)

	for msg := range out {
		msgBytes, err := cbor.Marshal(msg)
		if err != nil {
			return err
		}
		for idJ, r := range rounds {
			var m Message
			m.Content = r.MessageContent()
			m.Content.Init(group)
			if err = cbor.Unmarshal(msgBytes, &m); err != nil {
				return err
			}

			if m.From != idJ && (m.To == "" || m.To == idJ) {
				err = r.VerifyMessage(m)
				if err != nil {
					return err
				}
				err = r.StoreMessage(m)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
