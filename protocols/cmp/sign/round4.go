package sign

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zklogstar "github.com/taurusgroup/multi-party-sig/pkg/zk/logstar"
)

var _ round.Round = (*round4)(nil)

type round4 struct {
	*round3
	// DeltaShares[j] = δⱼ
	DeltaShares map[party.ID]curve.Scalar

	// BigDeltaShares[j] = Δⱼ = [kⱼ]•Γⱼ
	BigDeltaShares map[party.ID]curve.Point

	// Gamma = ∑ᵢ Γᵢ
	Gamma curve.Point

	// ChiShare = χᵢ
	ChiShare curve.Scalar
}

type message4 struct {
	ProofLog *zklogstar.Proof
}

type broadcast4 struct {
	round.NormalBroadcastContent
	// DeltaShare = δⱼ
	DeltaShare curve.Scalar
	// BigDeltaShare = Δⱼ = [kⱼ]•Γⱼ
	BigDeltaShare curve.Point
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - store δⱼ, Δⱼ
func (r *round4) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast4)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.DeltaShare.IsZero() || body.BigDeltaShare.IsIdentity() {
		return round.ErrNilFields
	}
	r.BigDeltaShares[msg.From] = body.BigDeltaShare
	r.DeltaShares[msg.From] = body.DeltaShare
	return nil
}

// VerifyMessage implements round.Round.
//
// - Verify Π(log*)(ϕ''ᵢⱼ, Δⱼ, Γ).
func (r *round4) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message4)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	zkLogPublic := zklogstar.Public{
		C:      r.K[from],
		X:      r.BigDeltaShares[from],
		G:      r.Gamma,
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}
	if !body.ProofLog.Verify(r.HashForID(from), zkLogPublic) {
		return errors.New("failed to validate log proof")
	}

	return nil
}

// StoreMessage implements round.Round.
func (round4) StoreMessage(round.Message) error {
	return nil
}

// Finalize implements round.Round
//
// - set δ = ∑ⱼ δⱼ
// - set Δ = ∑ⱼ Δⱼ
// - verify Δ = [δ]G
// - compute σᵢ = rχᵢ + kᵢm.
func (r *round4) Finalize(out chan<- *round.Message) (round.Session, error) {
	// δ = ∑ⱼ δⱼ
	// Δ = ∑ⱼ Δⱼ
	Delta := r.Group().NewScalar()
	BigDelta := r.Group().NewPoint()
	for _, j := range r.PartyIDs() {
		Delta.Add(r.DeltaShares[j])
		BigDelta = BigDelta.Add(r.BigDeltaShares[j])
	}

	// Δ == [δ]G
	deltaComputed := Delta.ActOnBase()
	if !deltaComputed.Equal(BigDelta) {
		return r.AbortRound(errors.New("computed Δ is inconsistent with [δ]G")), nil
	}

	deltaInv := r.Group().NewScalar().Set(Delta).Invert() // δ⁻¹
	BigR := deltaInv.Act(r.Gamma)                         // R = [δ⁻¹] Γ
	R := BigR.XScalar()                                   // r = R|ₓ

	// km = Hash(m)⋅kᵢ
	km := curve.FromHash(r.Group(), r.Message)
	km.Mul(r.KShare)

	// σᵢ = rχᵢ + kᵢm
	SigmaShare := r.Group().NewScalar().Set(R).Mul(r.ChiShare).Add(km)

	// Send to all
	err := r.BroadcastMessage(out, &broadcast5{SigmaShare: SigmaShare})
	if err != nil {
		return r, err
	}
	return &round5{
		round4:      r,
		SigmaShares: map[party.ID]curve.Scalar{r.SelfID(): SigmaShare},
		Delta:       Delta,
		BigDelta:    BigDelta,
		BigR:        BigR,
		R:           R,
	}, nil
}

// RoundNumber implements round.Content.
func (message4) RoundNumber() round.Number { return 4 }

// MessageContent implements round.Round.
func (r *round4) MessageContent() round.Content {
	return &message4{
		ProofLog: zklogstar.Empty(r.Group()),
	}
}

// RoundNumber implements round.Content.
func (broadcast4) RoundNumber() round.Number { return 4 }

// BroadcastContent implements round.BroadcastRound.
func (r *round4) BroadcastContent() round.BroadcastContent {
	return &broadcast4{
		DeltaShare:    r.Group().NewScalar(),
		BigDeltaShare: r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round4) Number() round.Number { return 4 }
