package sign

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
	zklogstar "github.com/taurusgroup/cmp-ecdsa/pkg/zk/logstar"
)

type round3 struct {
	*round2
	// Gamma = ∑ᵢ Γᵢ
	Gamma *curve.Point

	// ChiShare = χᵢ
	ChiShare *curve.Scalar
}

// ProcessMessage implements round.Round
//
// - verify Hash(ssid, K₁, G₁, …, Kₙ, Gₙ)
// - store MtA data
// - verify zkproofs affg (2x) zklog*
func (r *round3) ProcessMessage(from party.ID, content message.Content) error {
	body := content.(*Sign3)
	partyJ := r.Parties[from]

	if !bytes.Equal(body.EchoHash, r.EchoHash) {
		return ErrRound3EchoHash
	}

	if !body.DeltaMtA.VerifyAffG(r.HashForID(from), body.BigGammaShare, r.Self.K, partyJ.Public, r.Self.Public, nil) {
		return ErrRound3ZKAffGDeltaMtA
	}
	if !body.ChiMtA.VerifyAffG(r.HashForID(from), partyJ.ECDSA, r.Self.K, partyJ.Public, r.Self.Public, nil) {
		return ErrRound3ZKAffGChiMtA
	}

	zkLogPublic := zklogstar.Public{
		C:      partyJ.G,
		X:      body.BigGammaShare,
		Prover: partyJ.Paillier,
		Aux:    r.Self.Pedersen,
	}
	if !body.ProofLog.Verify(r.HashForID(from), zkLogPublic) {
		return ErrRound3ZKLog
	}

	partyJ.BigGammaShare = body.BigGammaShare

	// δᵢⱼ = αᵢⱼ + βᵢⱼ
	deltaShareAlpha, err := r.Secret.Paillier.Dec(body.DeltaMtA.D)
	if err != nil {
		return fmt.Errorf("failed to decrypt delta alpha share: %w", err)
	}
	deltaShare := curve.NewScalarBigInt(deltaShareAlpha)
	deltaShare.Add(deltaShare, partyJ.DeltaMtA.Beta)
	partyJ.DeltaShareMtA = deltaShare
	// χᵢⱼ = α̂ᵢⱼ +  ̂βᵢⱼ
	chiShareAlpha, err := r.Secret.Paillier.Dec(body.ChiMtA.D)
	if err != nil {
		return fmt.Errorf("failed to decrypt chi alpha share: %w", err)
	}
	chiShare := curve.NewScalarBigInt(chiShareAlpha)
	chiShare.Add(chiShare, partyJ.ChiMtA.Beta)
	partyJ.ChiShareMtA = chiShare
	return nil
}

// GenerateMessages implements round.Round
//
// - Γ = ∑ⱼ Γⱼ
// - Δᵢ = [kᵢ]Γ
// - δᵢ = γᵢ kᵢ + ∑ⱼ δᵢⱼ
// - χᵢ = xᵢ kᵢ + ∑ⱼ χᵢⱼ
func (r *round3) GenerateMessages(out chan<- *message.Message) error {
	// Γ = ∑ⱼ Γⱼ
	r.Gamma = curve.NewIdentityPoint()
	for _, partyJ := range r.Parties {
		r.Gamma.Add(r.Gamma, partyJ.BigGammaShare)
	}

	// Δᵢ = [kᵢ]Γ
	r.Self.BigDeltaShare = curve.NewIdentityPoint().ScalarMult(r.KShare, r.Gamma)

	// δᵢ = γᵢ kᵢ
	r.Self.DeltaShare = curve.NewScalar().Multiply(r.GammaShare, r.KShare)

	// χᵢ = xᵢ kᵢ
	r.ChiShare = curve.NewScalar().Multiply(r.Secret.ECDSA, r.KShare)

	for j, partyJ := range r.Parties {
		if j == r.Self.ID {
			continue
		}
		// δᵢ += αᵢⱼ + βᵢⱼ
		r.Self.DeltaShare.Add(r.Self.DeltaShare, partyJ.DeltaShareMtA)

		// χᵢ += α̂ᵢⱼ +  ̂βᵢⱼ
		r.ChiShare.Add(r.ChiShare, partyJ.ChiShareMtA)
	}

	zkPrivate := zklogstar.Private{
		X:   r.KShare.BigInt(),
		Rho: r.KNonce,
	}

	for j, partyJ := range r.Parties {
		if j == r.Self.ID {
			continue
		}

		proofLog := zklogstar.NewProof(r.HashForID(r.Self.ID), zklogstar.Public{
			C:      r.Self.K,
			X:      r.Self.BigDeltaShare,
			G:      r.Gamma,
			Prover: r.Self.Paillier,
			Aux:    partyJ.Pedersen,
		}, zkPrivate)

		msg := r.MarshalMessage(&Sign4{
			DeltaShare:    r.Self.DeltaShare,
			BigDeltaShare: r.Self.BigDeltaShare,
			ProofLog:      proofLog,
		}, j)
		if err := r.SendMessage(msg, out); err != nil {
			return err
		}
	}

	return nil
}

// Next implements round.Round
func (r *round3) Next() round.Round { return &round4{round3: r} }

// MessageContent implements round.Round
func (r *round3) MessageContent() message.Content { return &Sign3{} }

// Validate implements message.Content
func (m *Sign3) Validate() error {
	if m == nil {
		return errors.New("sign.round2: message is nil")
	}
	if m.BigGammaShare == nil || m.DeltaMtA == nil || m.ChiMtA == nil || m.ProofLog == nil {
		return errors.New("sign.round2: message contains nil fields")
	}
	if err := m.DeltaMtA.Validate(); err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if err := m.ChiMtA.Validate(); err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	return nil
}

// RoundNumber implements message.Content
func (m *Sign3) RoundNumber() types.RoundNumber { return 3 }

func (m *MtAMessage) Validate() error {
	if m.D == nil || m.F == nil || m.Proof == nil {
		return errors.New("sign.mta: message contains nil fields")
	}
	return nil
}
