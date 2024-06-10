package repair

import (
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type round2 struct {
	*round1
	deltas map[party.ID]curve.Scalar
}

type message2 struct {
	Delta curve.Scalar
}

func (*message2) RoundNumber() round.Number { return 2 }

func (r *round2) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	return nil
}

func (r *round2) StoreMessage(msg round.Message) error {
	if r.privateShare == nil {
		// lost share does nothing until round 3
		return nil
	}
	from, body := msg.From, msg.Content.(*message2)
	// The lost share sends us a dummy message due to library requirements.
	if from != r.lostID {
		r.deltas[from] = body.Delta
	}
	return nil
}

// MessageContent implements round.Round.
func (r *round2) MessageContent() round.Content {
	return &message2{Delta: r.Group().NewScalar()}
}

// Number implements round.Round.
func (*round2) Number() round.Number { return 2 }

// Finalize implements round.Round
//
// Round 2 generates the `sigma` values from all `deltas` received from `helpers`
// to help the lost share recover its secret.
// `sigma` is the sum of all deltas.
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	dummyMsg := &message3{r.Group().NewScalar()}
	if r.privateShare == nil {
		// The lost share does nothing until round 3.
		// Library internals, however, require that each share send a message to the other shares
		// before proceeding to round finalization, so we send a dummy message here.
		for _, id := range r.helpers {
			if err := r.SendMessage(out, dummyMsg, id); err != nil {
				return r, err
			}
		}
		return &round3{round2: r, sigmas: make(map[party.ID]curve.Scalar, len(r.helpers))}, nil
	}
	sigma := r.Group().NewScalar()
	for _, delta := range r.deltas {
		sigma = sigma.Add(delta)
	}

	if err := r.SendMessage(out, &message3{sigma}, r.lostID); err != nil {
		return r, err
	}
	// to satisfy the library, send dummy messages to the helpers
	for _, id := range r.helpers {
		if id == r.SelfID() {
			continue
		}
		if err := r.SendMessage(out, dummyMsg, id); err != nil {
			return r, err
		}
	}
	return &round3{round2: r}, nil
}
