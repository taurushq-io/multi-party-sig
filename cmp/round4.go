package cmp

import (
	"errors"
	"time"
)

type round4 struct {
	*round3
}

func (r *round4) GetMessagesOut() ([]*Message, error) {
	r.Lock()
	defer r.Unlock()

	if !r.canExecute() {
		return nil, errors.New("fail")
	}

	r.log.Info().Msg("Starting Round")
	defer func(t time.Time) {
		d := time.Since(t)
		r.log.Info().Dur("t", d).Msg("Finished Round")
		r.debug.TimeRound4 = d
	}(time.Now())

	selfParty := r.parties[r.selfID]

	for from, msg := range r.msgs3 {
		prover := r.parties[from]

		if err := msg.Proof.Verify(r.group, prover.Paillier, selfParty.Paillier, selfParty.Pedersen, prover.K, msg.DeltaPoint, r.Gamma); err != nil {
			r.log.Error().Err(err).Msg("zk failed")
		}

		prover.delta = msg.DeltaScalar
		prover.Delta = msg.DeltaPoint
	}

	delta := r.group.Scalar().Zero()
	Delta := r.group.Point().Null()

	for _, party := range r.parties {
		delta.Add(delta, party.delta)
		Delta.Add(Delta, party.Delta)
	}

	if !r.group.Point().Mul(delta, nil).Equal(Delta) {
		r.Log().Error().Msg("Failed to validate delta")
	}

	deltaInv := r.group.Scalar().Inv(delta)
	r.R = r.group.Point().Mul(deltaInv, r.Gamma)

	Rx := GetXCoord(r.R)

	rx := r.group.Scalar().Mul(Rx, r.chi)
	km := r.group.Scalar().Mul(r.k, r.message)

	selfParty.sigma = r.group.Scalar().Add(rx, km)

	msgs := make([]*Message, len(r.otherIDs))
	for i, otherPartyID := range r.otherIDs {
		msgs[i] = &Message{
			From: r.selfID,
			To:   otherPartyID,
			Msg4: &msg4{Sigma: selfParty.sigma},
		}
	}

	return msgs, nil
}

func (r *round4) NextRound() Round {
	r.number++
	r.log = r.log.With().Int("round", r.number).Logger()
	r5 := &round5{
		round4: r,
	}
	return r5
}
