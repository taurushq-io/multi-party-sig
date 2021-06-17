package sign

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
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
func (r *round4) ProcessMessage(msg round.Message) error {
	j := msg.GetHeader().From
	partyJ := r.parties[j]
	body := msg.(*Message).GetSign3()

	zkLogPublic := zklogstar.Public{
		C:      partyJ.K,
		X:      body.BigDeltaShare,
		G:      r.Gamma,
		Prover: partyJ.Paillier,
		Aux:    r.Self.Pedersen,
	}
	if !body.ProofLog.Verify(r.Hash.CloneWithID(j), zkLogPublic) {
		return fmt.Errorf("sign.round4.ProcessMessage(): party %s: log proof failed to verify", j)
	}

	partyJ.BigDeltaShare = body.BigDeltaShare
	partyJ.DeltaShare = body.DeltaShare

	return partyJ.AddMessage(msg)
}

// GenerateMessages implements round.Round
//
// - set δ = ∑ⱼ δⱼ
// - set Δ = ∑ⱼ Δⱼ
// - verify Δ = [δ]G
// - compute σᵢ = rχᵢ + kᵢm
func (r *round4) GenerateMessages() ([]round.Message, error) {
	// δ = ∑ⱼ δⱼ
	// Δ = ∑ⱼ Δⱼ
	r.Delta = curve.NewScalar()
	r.BigDelta = curve.NewIdentityPoint()
	for _, partyJ := range r.parties {
		r.Delta.Add(r.Delta, partyJ.DeltaShare)
		r.BigDelta.Add(r.BigDelta, partyJ.BigDeltaShare)
	}

	// Δ == [δ]G
	deltaComputed := curve.NewIdentityPoint().ScalarBaseMult(r.Delta)
	if !deltaComputed.Equal(r.BigDelta) {
		return nil, fmt.Errorf("sign.round4.GenerateMessages(): computed Δ is inconsistent with [δ]G")
	}

	deltaInv := curve.NewScalar().Invert(r.Delta)                   // δ⁻¹
	r.BigR = curve.NewIdentityPoint().ScalarMult(deltaInv, r.Gamma) // R = [δ⁻¹] Γ
	r.r = r.BigR.XScalar()                                          // r = R|ₓ

	// km = Hash(m)⋅kᵢ
	km := curve.NewScalar().SetHash(r.Message)
	km.Multiply(km, r.KShare)

	// σᵢ = rχᵢ + kᵢm
	r.Self.SigmaShare = curve.NewScalar().MultiplyAdd(r.r, r.ChiShare, km)

	return NewMessageSign4(r.SelfID, &Sign4{SigmaShare: r.Self.SigmaShare}), nil
}

// Finalize implements round.Round
func (r *round4) Finalize() (round.Round, error) {
	return &output{
		round4: r,
	}, nil
}

func (r *round4) MessageType() round.MessageType {
	return MessageTypeSign3
}
