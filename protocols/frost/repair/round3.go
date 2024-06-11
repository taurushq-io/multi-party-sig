package repair

import (
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type round3 struct {
	*round2
	sigmas map[party.ID]curve.Scalar
}

type message3 struct {
	Sigma curve.Scalar
}

func (message3) RoundNumber() round.Number { return 3 }

func (r *round3) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	return nil
}

func (r *round3) StoreMessage(msg round.Message) error {
	if r.privateShare != nil {
		// only the lost share does anything in round 3
		return nil
	}
	from, body := msg.From, msg.Content.(*message3)
	r.sigmas[from] = body.Sigma
	return nil
}

func (r *round3) MessageContent() round.Content {
	return &message3{Sigma: r.Group().NewScalar()}
}

// Number implements round.Round
func (*round3) Number() round.Number { return 3 }

// Finalize implements round.Round
//
// Round 3 only involves the lost share:
// It sums contributed sigmas to create a new secret share.
func (r *round3) Finalize(chan<- *round.Message) (round.Session, error) {
	if r.privateShare != nil {
		// only the lost share needs to compute the secret
		// we return zero scalar for consistency
		return r.ResultRound(r.Group().NewScalar()), nil
	}

	share := r.Group().NewScalar()
	for _, sigma := range r.sigmas {
		share = share.Add(sigma)
	}

	return r.ResultRound(share), nil
}
