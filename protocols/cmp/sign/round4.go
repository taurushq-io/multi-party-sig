package sign

import (
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/types"
	zklogstar "github.com/taurusgroup/multi-party-sig/pkg/zk/logstar"
)

var _ round.Round = (*round4)(nil)

type round4 struct {
	*round3
	// DeltaShares[j] = δⱼ
	DeltaShares map[party.ID]*curve.Scalar

	// BigDeltaShares[j] = Δⱼ = [kⱼ]•Γⱼ
	BigDeltaShares map[party.ID]*curve.Point

	// Gamma = ∑ᵢ Γᵢ
	Gamma *curve.Point

	// ChiShare = χᵢ
	ChiShare *curve.Scalar
}

type Sign4 struct {
	// DeltaShare = δⱼ
	DeltaShare *curve.Scalar
	// BigDeltaShare = Δⱼ = [kⱼ]•Γⱼ
	BigDeltaShare *curve.Point
	ProofLog      *zklogstar.Proof
}

// VerifyMessage implements round.Round.
//
// - Verify Π(log*)(ϕ''ᵢⱼ, Δⱼ, Γ).
func (r *round4) VerifyMessage(from party.ID, to party.ID, content message.Content) error {
	body, ok := content.(*Sign4)
	if !ok || body == nil {
		return message.ErrInvalidContent
	}

	if body.DeltaShare == nil || body.BigDeltaShare == nil || body.ProofLog == nil {
		return message.ErrNilContent
	}

	zkLogPublic := zklogstar.Public{
		C:      r.K[from],
		X:      body.BigDeltaShare,
		G:      r.Gamma,
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}
	if !body.ProofLog.Verify(r.HashForID(from), zkLogPublic) {
		return ErrRound4ZKLog
	}

	return nil
}

// StoreMessage implements round.Round.
//
// - store Δⱼ, δⱼ.
func (r *round4) StoreMessage(from party.ID, content message.Content) error {
	body := content.(*Sign4)
	r.BigDeltaShares[from] = body.BigDeltaShare
	r.DeltaShares[from] = body.DeltaShare
	return nil
}

// Finalize implements round.Round
//
// - set δ = ∑ⱼ δⱼ
// - set Δ = ∑ⱼ Δⱼ
// - verify Δ = [δ]G
// - compute σᵢ = rχᵢ + kᵢm.
func (r *round4) Finalize(out chan<- *message.Message) (round.Round, error) {
	// δ = ∑ⱼ δⱼ
	// Δ = ∑ⱼ Δⱼ
	Delta := curve.NewScalar()
	BigDelta := curve.NewIdentityPoint()
	for _, j := range r.PartyIDs() {
		Delta.Add(Delta, r.DeltaShares[j])
		BigDelta.Add(BigDelta, r.BigDeltaShares[j])
	}

	// Δ == [δ]G
	deltaComputed := curve.NewIdentityPoint().ScalarBaseMult(Delta)
	if !deltaComputed.Equal(BigDelta) {
		return nil, ErrRound4BigDelta
	}

	deltaInv := curve.NewScalar().Invert(Delta)                    // δ⁻¹
	BigR := curve.NewIdentityPoint().ScalarMult(deltaInv, r.Gamma) // R = [δ⁻¹] Γ
	R := BigR.XScalar()                                            // r = R|ₓ

	// km = Hash(m)⋅kᵢ
	km := curve.NewScalar().SetHash(r.Message)
	km.Multiply(km, r.KShare)

	// σᵢ = rχᵢ + kᵢm
	SigmaShare := curve.NewScalar().MultiplyAdd(R, r.ChiShare, km)

	// Send to all
	msg := r.MarshalMessage(&SignOutput{SigmaShare: SigmaShare}, r.OtherPartyIDs()...)
	if err := r.SendMessage(msg, out); err != nil {
		return r, err
	}
	return &output{
		round4:      r,
		SigmaShares: map[party.ID]*curve.Scalar{r.SelfID(): SigmaShare},
		Delta:       Delta,
		BigDelta:    BigDelta,
		BigR:        BigR,
		R:           R,
	}, nil
}

// MessageContent implements round.Round.
func (r *round4) MessageContent() message.Content { return &Sign4{} }

// RoundNumber implements message.Content.
func (m *Sign4) RoundNumber() types.RoundNumber { return 4 }
