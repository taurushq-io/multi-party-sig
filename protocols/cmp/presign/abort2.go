package presign

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zklog "github.com/taurusgroup/multi-party-sig/pkg/zk/log"
)

var _ round.Round = (*abort2)(nil)

type abort2 struct {
	*presign7
	// YHat[j] = Ŷⱼ = bⱼ⋅Yⱼ
	YHat    map[party.ID]curve.Point
	KShares map[party.ID]curve.Scalar
	// ChiAlphas[j][k] = α̂ⱼₖ
	ChiAlphas map[party.ID]map[party.ID]curve.Scalar
}

type broadcastAbort2 struct {
	round.NormalBroadcastContent
	// YHat = Ŷⱼ = bⱼ⋅Yⱼ
	YHat      curve.Point
	YHatProof *zklog.Proof
	KProof    *abortNth
	ChiProofs map[party.ID]*abortNth
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *abort2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcastAbort2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	alphas := make(map[party.ID]curve.Scalar, len(body.ChiProofs))
	for id, chiProof := range body.ChiProofs {
		alphas[id] = r.Group().NewScalar().SetNat(chiProof.Plaintext.Mod(r.Group().Order()))
	}
	r.ChiAlphas[from] = alphas
	r.YHat[from] = body.YHat
	r.KShares[from] = r.Group().NewScalar().SetNat(body.KProof.Plaintext.Mod(r.Group().Order()))

	if !body.YHatProof.Verify(r.HashForID(from), zklog.Public{
		H: r.ElGamalK[from].L,
		X: r.ElGamal[from],
		Y: body.YHat,
	}) {
		return errors.New("failed to verify YHat log proof")
	}

	public := r.Paillier[from]
	if !body.KProof.Verify(r.HashForID(from), public, r.K[from]) {
		return errors.New("failed to verify validity of k")
	}

	for id, chiProof := range body.ChiProofs {
		if !chiProof.Verify(r.HashForID(from), public, r.ChiCiphertext[from][id]) {
			return errors.New("failed to validate Delta MtA Nth proof")
		}
	}
	return nil
}

// VerifyMessage implements round.Round.
func (abort2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (abort2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
func (r *abort2) Finalize(chan<- *round.Message) (round.Session, error) {
	var culprits []party.ID
	for _, j := range r.OtherPartyIDs() {
		// M = Ŷⱼ + kⱼ⋅Xⱼ
		M := r.Group().NewPoint().Add(r.YHat[j]).Add(r.KShares[j].Act(r.ECDSA[j]))
		for _, l := range r.PartyIDs() {
			if l == j {
				continue
			}
			M = M.Add(r.ChiAlphas[j][l].ActOnBase()) // α̂ⱼₗ⋅G
			M = M.Add(r.KShares[l].Act(r.ECDSA[j]))  // kₗ⋅Xⱼ
			M = M.Sub(r.ChiAlphas[l][j].ActOnBase()) // -α̂ₗⱼ⋅G

		}

		if !M.Equal(r.ElGamalK[j].M) {
			culprits = append(culprits, j)
		}
	}

	return r.AbortRound(errors.New("abort2: detected culprit"), culprits...), nil
}

// MessageContent implements round.Round.
func (abort2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcastAbort2) RoundNumber() round.Number { return 8 }

// BroadcastContent implements round.BroadcastRound.
func (r *abort2) BroadcastContent() round.BroadcastContent {
	return &broadcastAbort2{
		YHat:      r.Group().NewPoint(),
		YHatProof: zklog.Empty(r.Group()),
	}
}

// Number implements round.Round.
func (abort2) Number() round.Number { return 8 }
