package cmpold

import (
	"errors"
	"time"

	"github.com/taurusgroup/cmp-ecdsa/pkg/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zkold"
)

type round2 struct {
	*round1
}

func (r *round2) GetMessagesOut() ([]*Message, error) {
	r.Lock()
	defer r.Unlock()

	if !r.canExecute() {
		return nil, errors.New("fail")
	}

	r.log.Info().Msg("Starting Round")
	defer func(t time.Time) {
		d := time.Since(t)
		r.log.Info().Dur("t", d).Msg("Finished Round")
		r.debug.TimeRound2 = d
	}(time.Now())

	selfParty := r.parties[r.selfID]

	for from, msg := range r.msgs1 {
		prover := r.parties[from]

		if err := msg.Proof.Verify(prover.Paillier, selfParty.Paillier, selfParty.Pedersen, msg.K); err != nil {
			r.log.Error().Err(err).Msg("zkold failed")
		}

		prover.K = msg.K
		prover.G = msg.G
	}

	selfParty.Gamma = r.group.Point().Mul(r.gamma, nil)

	out := make([]*Message, len(r.otherIDs))
	for i, otherPartyID := range r.otherIDs {
		verifier := r.parties[otherPartyID]

		betaNeg := arith.MustSample(zkold.TwoPowLPrime)
		beta := r.group.Scalar().SetBytes(betaNeg.Bytes())
		D, s := verifier.Paillier.AffineEnc(verifier.K, arith.GetBigInt(r.gamma), arith.GetBigInt(beta))
		F, rho := selfParty.Paillier.Enc(arith.GetBigInt(beta))
		proofGamma := zkold.NewAffineGroupCommitmentRange(r.group, selfParty.Paillier, verifier.Paillier, verifier.Pedersen, verifier.K, D, F, selfParty.Gamma, r.gamma, beta, s, rho)
		verifier.beta = beta.Neg(beta)

		betaNegHat := arith.MustSample(zkold.TwoPowLPrime)
		betaHat := r.group.Scalar().SetBytes(betaNegHat.Bytes())
		DHat, sHat := verifier.Paillier.AffineEnc(verifier.K, arith.GetBigInt(r.secret.ECDSA), arith.GetBigInt(betaHat))
		FHat, rhoHat := selfParty.Paillier.Enc(arith.GetBigInt(betaHat))
		proofX := zkold.NewAffineGroupCommitmentRange(r.group, selfParty.Paillier, verifier.Paillier, verifier.Pedersen, verifier.K, DHat, FHat, selfParty.ECDSA, r.secret.ECDSA, betaHat, sHat, rhoHat)
		verifier.betaHat = betaHat.Neg(betaHat)

		proofLog := zkold.NewLog(r.group, selfParty.Paillier, verifier.Paillier, verifier.Pedersen, selfParty.G, selfParty.Gamma, r.group.Point().Base(), r.gamma, r.gammaEncNonce)

		out[i] = &Message{
			From: r.selfID,
			To:   otherPartyID,
			Msg2: &msg2{
				D:          D,
				F:          F,
				DHat:       DHat,
				FHat:       FHat,
				ProofGamma: proofGamma,
				ProofX:     proofX,
				ProofLog:   proofLog,
				Gamma:      selfParty.Gamma,
			},
		}
	}

	return out, nil
}

func (r *round2) NextRound() Round {
	r.number += 1
	r.log = r.log.With().Int("round", r.number).Logger()
	r3 := &round3{
		round2: r,
	}
	return r3
}
