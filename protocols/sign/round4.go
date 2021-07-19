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

type round4 struct {
	*round3
	// Delta = δ = ∑ⱼ δⱼ
	// computed from received shares
	Delta *curve.Scalar

	// BigDelta = Δ = ∑ⱼ Δⱼ
	BigDelta *curve.Point

	// R = [δ⁻¹] Γ
	BigR *curve.Point

	// r = R|ₓ
	r *curve.Scalar
}

// ProcessMessage implements round.Round
//
// - Get Δⱼ, δⱼ, ϕ''ᵢⱼ
// - Verify Π(log*)(ϕ''ᵢⱼ, Δⱼ, Γ)
func (r *round4) ProcessMessage(from party.ID, content message.Content) error {
	body := content.(*Sign4)
	partyJ := r.Parties[from]

	zkLogPublic := zklogstar.Public{
		C:      partyJ.K,
		X:      body.BigDeltaShare,
		G:      r.Gamma,
		Prover: partyJ.Paillier,
		Aux:    r.Self.Pedersen,
	}
	if !body.ProofLog.Verify(r.HashForID(from), zkLogPublic) {
		return ErrRound4ZKLog
	}

	partyJ.BigDeltaShare = body.BigDeltaShare
	partyJ.DeltaShare = body.DeltaShare
	return nil
}

// GenerateMessages implements round.Round
//
// - set δ = ∑ⱼ δⱼ
// - set Δ = ∑ⱼ Δⱼ
// - verify Δ = [δ]G
// - compute σᵢ = rχᵢ + kᵢm
func (r *round4) GenerateMessages(out chan<- *message.Message) error {
	// δ = ∑ⱼ δⱼ
	// Δ = ∑ⱼ Δⱼ
	r.Delta = curve.NewScalar()
	r.BigDelta = curve.NewIdentityPoint()
	for _, partyJ := range r.Parties {
		r.Delta.Add(r.Delta, partyJ.DeltaShare)
		r.BigDelta.Add(r.BigDelta, partyJ.BigDeltaShare)
	}

	// Δ == [δ]G
	deltaComputed := curve.NewIdentityPoint().ScalarBaseMult(r.Delta)
	if !deltaComputed.Equal(r.BigDelta) {
		return ErrRound4BigDelta
	}

	deltaInv := curve.NewScalar().Invert(r.Delta)                   // δ⁻¹
	r.BigR = curve.NewIdentityPoint().ScalarMult(deltaInv, r.Gamma) // R = [δ⁻¹] Γ
	r.r = r.BigR.XScalar()                                          // r = R|ₓ

	// km = Hash(m)⋅kᵢ
	km := curve.NewScalar().SetHash(r.Message)
	km.Multiply(km, r.KShare)

	// σᵢ = rχᵢ + kᵢm
	r.Self.SigmaShare = curve.NewScalar().MultiplyAdd(r.r, r.ChiShare, km)

	// Send to all
	msg := r.MarshalMessage(&SignOutput{SigmaShare: r.Self.SigmaShare}, r.OtherPartyIDs()...)
	if err := r.SendMessage(msg, out); err != nil {
		return err
	}
	return nil
}

// Next implements round.Round
func (r *round4) Next() round.Round {
	return &output{
		round4: r,
	}
}

func (r *round4) MessageContent() message.Content {
	return &Sign4{}
}

func (m *Sign4) Validate() error {
	if m == nil {
		return errors.New("sign.round3: message is nil")
	}
	if m.DeltaShare == nil || m.BigDeltaShare == nil || m.ProofLog == nil {
		return errors.New("sign.round3: message contains nil fields")
	}

	return nil
}

func (m *Sign4) RoundNumber() types.RoundNumber {
	return 4
}
