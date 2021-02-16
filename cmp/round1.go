package cmp

import (
	"errors"
	"github.com/taurusgroup/cmp-ecdsa/arith"
	"github.com/taurusgroup/cmp-ecdsa/zk"
	"time"
)

type round1 struct {
	*round
}

func (r *round1) GetMessagesOut() ([]*Message, error) {
	r.Lock()
	defer r.Unlock()

	if !r.canExecute() {
		return nil, errors.New("fail")
	}

	r.log.Info().Msg("Starting Round")
	defer func(t time.Time) {
		d := time.Since(t)
		r.log.Info().Dur("t", d).Msg("Finished Round")
		r.debug.TimeRound1 = d
	}(time.Now())

	selfParty := r.parties[r.selfID]

	stream := r.group.RandomStream()
	r.k = r.group.Scalar().Pick(stream)
	r.gamma = r.group.Scalar().Pick(stream)

	selfParty.K, r.kEncNonce = selfParty.Paillier.Enc(arith.GetBigInt(r.k))
	selfParty.G, r.gammaEncNonce = selfParty.Paillier.Enc(arith.GetBigInt(r.gamma))

	out := make([]*Message, len(r.otherIDs))

	for i, otherPartyID := range r.otherIDs {
		otherParty := r.parties[otherPartyID]

		proof := zk.NewEncryptionInRange(selfParty.Paillier, otherParty.Paillier, otherParty.Pedersen, selfParty.K, arith.GetBigInt(r.k), r.kEncNonce)

		out[i] = &Message{
			From: r.selfID,
			To:   otherPartyID,
			Msg1: &msg1{
				Proof: proof,
				K:     selfParty.K,
				G:     selfParty.G,
			},
		}
	}

	return out, nil
}

func (r *round1) NextRound() Round {
	r.number += 1
	r.log = r.log.With().Int("round", r.number).Logger()
	r2 := &round2{
		round1: r,
	}
	return r2
}
