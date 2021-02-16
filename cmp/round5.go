package cmp

import (
	"errors"
	"time"
)

type round5 struct {
	*round4
}

func (r *round5) GetMessagesOut() ([]*Message, error) {
	r.Lock()
	defer r.Unlock()

	if !r.canExecute() {
		return nil, errors.New("fail")
	}

	r.log.Info().Msg("Starting Round")
	defer func(t time.Time) {
		d := time.Since(t)
		r.log.Info().Dur("t", d).Msg("Finished Round")
		r.debug.TimeRound5 = d
	}(time.Now())

	for from, msg := range r.msgs4 {
		r.parties[from].sigma = msg.Sigma
	}

	sig := r.group.Scalar().Zero()

	for _, party := range r.parties {
		sig.Add(sig, party.sigma)
	}
	r.sigma = sig

	if r.sig == nil {
		signature := &Signature{
			M: r.message,
			R: r.R,
			S: r.sigma,
		}
		r.sig = signature
		r.completion()
	}

	return nil, nil
}

func (r *round5) NextRound() Round {
	return nil
}

func (r *round5) Signature() *Signature {
	return r.sig
}
