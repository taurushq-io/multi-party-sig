package sign

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zklogstar "github.com/taurusgroup/cmp-ecdsa/pkg/zk/logstar"
)

type round4 struct {
	*round3
	// delta = δ = ∑ⱼ δⱼ
	// computed from received shares
	delta *curve.Scalar

	// Delta = Δ = ∑ⱼ Δⱼ
	Delta *curve.Point

	// R = [δ⁻¹] Γ
	R *curve.Point

	// r = R|ₓ
	r *curve.Scalar
}

// ProcessMessage implements round.Round
//
// - Get Δⱼ, δⱼ, ϕ''ᵢⱼ
// - Verify Π(log*)(ϕ''ᵢⱼ, Δⱼ, Γ)
func (round *round4) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFromID()
	partyJ := round.parties[j]

	body := msg.GetSign3()

	Delta, err := body.GetDeltaGroup().Unmarshal()
	if err != nil {
		return fmt.Errorf("sign.round4.ProcessMessage(): unmarshal Delta: %w", err)
	}
	delta, err := body.GetDelta().Unmarshal()
	if err != nil {
		return fmt.Errorf("sign.round4.ProcessMessage(): unmarshal delta: %w", err)
	}

	zkLogPublic := zklogstar.Public{
		C:      partyJ.K,
		X:      Delta,
		G:      round.Gamma,
		Prover: partyJ.Paillier,
		Aux:    round.thisParty.Pedersen,
	}
	if !zkLogPublic.Verify(round.H.CloneWithID(j), body.ProofLog) {
		return fmt.Errorf("sign.round4.ProcessMessage(): party %s: log proof failed to verify", j)
	}

	partyJ.Delta = Delta
	partyJ.delta = delta

	return partyJ.AddMessage(msg)
}

// GenerateMessages implements round.Round
//
// - set δ = ∑ⱼ δⱼ
// - set Δ = ∑ⱼ Δⱼ
// - verify Δ = [δ]G
// - compute σᵢ = rχᵢ + kᵢm
func (round *round4) GenerateMessages() ([]*pb.Message, error) {
	// δ = ∑ⱼ δⱼ
	round.delta = curve.NewScalar()
	// Δ = ∑ⱼ Δⱼ
	round.Delta = curve.NewIdentityPoint()
	for _, partyJ := range round.parties {
		round.delta.Add(round.delta, partyJ.delta)
		round.Delta.Add(round.Delta, partyJ.Delta)
	}

	// Δ == [δ]G
	deltaComputed := curve.NewIdentityPoint().ScalarBaseMult(round.delta)
	if !deltaComputed.Equal(round.Delta) {
		return nil, fmt.Errorf("sign.round4.GenerateMessages(): computed Δ is inconsistent with [δ]G")
	}

	deltaInv := curve.NewScalar().Invert(round.delta)                    // δ⁻¹
	round.R = curve.NewIdentityPoint().ScalarMult(deltaInv, round.Gamma) // R = [δ⁻¹] Γ
	round.r = round.R.X()                                                // r = R|ₓ

	// km = H(m)⋅kᵢ
	km := curve.NewScalar().SetHash(round.S.Message)
	km.Multiply(km, round.k)

	// σᵢ = rχᵢ + kᵢm
	round.thisParty.sigma = curve.NewScalar().MultiplyAdd(round.r, round.chi, km)

	return []*pb.Message{{
		Type:      pb.MessageType_TypeSign4,
		From:      round.SelfID,
		Broadcast: pb.Broadcast_Basic,
		Sign4:     &pb.Sign4{Sigma: pb.NewScalar(round.thisParty.sigma)},
	}}, nil
}

// Finalize implements round.Round
func (round *round4) Finalize() (round.Round, error) {
	return &output{
		round4: round,
	}, nil
}

func (round *round4) MessageType() pb.MessageType {
	return pb.MessageType_TypeSign3
}
