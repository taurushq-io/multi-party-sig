package xor

import (
	"crypto/rand"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// Round1 can embed round.Helper which provides useful methods handling messages.
type Round1 struct {
	*round.Helper
}

// VerifyMessage in the first round does nothing since no messages are expected.
func (r *Round1) VerifyMessage(round.Message) error { return nil }

// StoreMessage in the first round does nothing since no messages are expected.
func (r *Round1) StoreMessage(round.Message) error { return nil }

// Finalize uses the out channel to communicate messages to other parties.
func (r *Round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	xor, err := types.NewRID(rand.Reader)
	if err != nil {
		// return the round since we did not actually abort due to malicious behaviour.
		return r, err
	}
	// send the message to all other parties, and marshal it using the helper method which sets the appropriate headers.
	err = r.SendMessage(out, &Round2Message{xor}, "")
	if err != nil {
		return r, err
	}

	return &Round2{
		Round1:   r,
		received: map[party.ID]types.RID{r.SelfID(): xor},
	}, nil
}

// MessageContent returns an empty message.First as a placeholder indicating that no message is expected.
func (Round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (Round1) Number() round.Number { return 1 }
