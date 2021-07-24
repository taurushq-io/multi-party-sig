package sign

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
	zklogstar "github.com/taurusgroup/cmp-ecdsa/pkg/zk/logstar"
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

// ProcessMessage implements round.Round
//
// - Get Δⱼ, δⱼ, ϕ''ᵢⱼ
// - Verify Π(log*)(ϕ''ᵢⱼ, Δⱼ, Γ)
func (r *round4) ProcessMessage(j party.ID, content message.Content) error {
	body := content.(*Sign4)

	zkLogPublic := zklogstar.Public{
		C:      r.K[j],
		X:      body.BigDeltaShare,
		G:      r.Gamma,
		Prover: r.Public[j].Paillier,
		Aux:    r.Public[r.SelfID()].Pedersen,
	}
	if !body.ProofLog.Verify(r.HashForID(j), zkLogPublic) {
		return ErrRound4ZKLog
	}

	r.BigDeltaShares[j] = body.BigDeltaShare
	r.DeltaShares[j] = body.DeltaShare
	return nil
}

// Finalize implements round.Round
//
// - set δ = ∑ⱼ δⱼ
// - set Δ = ∑ⱼ Δⱼ
// - verify Δ = [δ]G
// - compute σᵢ = rχᵢ + kᵢm
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

// MessageContent implements round.Round
func (r *round4) MessageContent() message.Content { return &Sign4{} }

// Validate implements message.Content
func (m *Sign4) Validate() error {
	if m == nil {
		return errors.New("sign.round4: message is nil")
	}
	if m.DeltaShare == nil || m.BigDeltaShare == nil || m.ProofLog == nil {
		return errors.New("sign.round4: message contains nil fields")
	}

	return nil
}

// RoundNumber implements message.Content
func (m *Sign4) RoundNumber() types.RoundNumber { return 4 }
