package presign

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zkelog "github.com/taurusgroup/multi-party-sig/pkg/zk/elog"
	zklogstar "github.com/taurusgroup/multi-party-sig/pkg/zk/logstar"
)

var _ round.Round = (*presign5)(nil)

type presign5 struct {
	*presign4

	// BigGammaShare[j] = Γⱼ = [γⱼ]•G
	BigGammaShare map[party.ID]curve.Point
}

type message5 struct {
	// BigGammaShare = Γᵢ
	BigGammaShare curve.Point
	ProofLog      *zklogstar.Proof
}

// VerifyMessage implements round.Round.
func (r *presign5) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message5)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.BigGammaShare.IsIdentity() {
		return round.ErrNilFields
	}

	if !body.ProofLog.Verify(r.HashForID(msg.From), zklogstar.Public{
		C:      r.G[from],
		X:      body.BigGammaShare,
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}) {
		return errors.New("failed to validate log* proof for BigGammaShare")
	}

	return nil
}

// StoreMessage implements round.Round.
//
// - save Γⱼ
func (r *presign5) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*message5)
	r.BigGammaShare[from] = body.BigGammaShare
	return nil
}

// Finalize implements round.Round
//
// - compute Γ = ∑ⱼ Γⱼ
// - compute Δᵢ = kᵢ⋅Γ.
func (r *presign5) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Γ = ∑ⱼ Γⱼ
	Gamma := r.Group().NewPoint()
	for _, GammaJ := range r.BigGammaShare {
		Gamma = Gamma.Add(GammaJ)
	}

	// Δᵢ = kᵢ⋅Γ
	BigDeltaShare := r.KShare.Act(Gamma)

	proofLog := zkelog.NewProof(r.Group(), r.HashForID(r.SelfID()),
		zkelog.Public{
			E:             r.ElGamalK[r.SelfID()],
			ElGamalPublic: r.ElGamal[r.SelfID()],
			Base:          Gamma,
			Y:             BigDeltaShare,
		}, zkelog.Private{
			Y:      r.KShare,
			Lambda: r.ElGamalKNonce,
		})

	err := r.SendMessage(out, &message6{
		BigDeltaShare: BigDeltaShare,
		Proof:         proofLog,
	}, "")
	if err != nil {
		return r, err
	}

	return &presign6{
		presign5:       r,
		Gamma:          Gamma,
		BigDeltaShares: map[party.ID]curve.Point{r.SelfID(): BigDeltaShare},
	}, nil
}

// MessageContent implements round.Round.
func (r *presign5) MessageContent() round.Content {
	return &message5{
		BigGammaShare: r.Group().NewPoint(),
		ProofLog:      zklogstar.Empty(r.Group()),
	}
}

// Number implements round.Round.
func (presign5) Number() round.Number { return 5 }
