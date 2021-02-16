package cmp

import (
	"errors"
	"github.com/taurusgroup/cmp-ecdsa/zk"
	"time"
)

type round3 struct {
	*round2
}

func (r *round3) GetMessagesOut() ([]*Message, error) {
	r.Lock()
	defer r.Unlock()

	if !r.canExecute() {
		return nil, errors.New("fail")
	}

	r.log.Info().Msg("Starting Round")
	defer func(t time.Time) {
		d := time.Since(t)
		r.log.Info().Dur("t", d).Msg("Finished Round")
		r.debug.TimeRound3 = d
	}(time.Now())

	selfParty := r.parties[r.selfID]

	for from, msg := range r.msgs2 {
		prover := r.parties[from]

		if err := msg.ProofGamma.Verify(r.group, prover.Paillier, selfParty.Paillier, selfParty.Pedersen, selfParty.K, msg.D, msg.F, msg.Gamma); err != nil {
			r.log.Error().Err(err).Msg("zk failed")
		}

		if err := msg.ProofX.Verify(r.group, prover.Paillier, selfParty.Paillier, selfParty.Pedersen, selfParty.K, msg.DHat, msg.FHat, prover.ECDSA); err != nil {
			r.log.Error().Err(err).Msg("zk failed")
		}

		if err := msg.ProofLog.Verify(r.group, prover.Paillier, selfParty.Paillier, selfParty.Pedersen, prover.G, msg.Gamma, r.group.Point().Base()); err != nil {
			r.log.Error().Err(err).Msg("zk failed")
		}

		prover.Gamma = msg.Gamma

		a := r.secret.Paillier.Dec(msg.D)
		aHat := r.secret.Paillier.Dec(msg.DHat)
		prover.alpha = r.group.Scalar().SetBytes(a.Bytes())
		prover.alphaHat = r.group.Scalar().SetBytes(aHat.Bytes())

	}

	delta := r.group.Scalar().Mul(r.gamma, r.k)       // delta_i
	r.chi = r.group.Scalar().Mul(r.secret.ECDSA, r.k) // chi_i

	r.Gamma = r.parties[r.selfID].Gamma.Clone()

	for _, otherParty := range r.otherIDs {
		partyOther := r.parties[otherParty]

		delta.Add(delta, partyOther.alpha)
		delta.Add(delta, partyOther.beta)

		r.chi.Add(r.chi, partyOther.alphaHat)
		r.chi.Add(r.chi, partyOther.betaHat)

		r.Gamma.Add(r.Gamma, partyOther.Gamma)
	}

	msgs := make([]*Message, len(r.otherIDs))
	for i, otherPartyID := range r.otherIDs {
		verifier := r.parties[otherPartyID]

		selfParty.delta = delta
		selfParty.Delta = r.group.Point().Mul(r.k, r.Gamma)

		proof := zk.NewLog(r.group, selfParty.Paillier, verifier.Paillier, verifier.Pedersen, selfParty.K, selfParty.Delta, r.Gamma, r.k, r.kEncNonce)

		msgs[i] = &Message{
			From: r.selfID,
			To:   otherPartyID,
			Msg3: &msg3{
				Proof:       proof,
				DeltaScalar: selfParty.delta,
				DeltaPoint:  selfParty.Delta,
			},
		}
	}

	return msgs, nil
}

func (r *round3) NextRound() Round {
	r.number += 1
	r.log = r.log.With().Int("round", r.number).Logger()
	r4 := &round4{
		round3: r,
	}
	return r4
}
